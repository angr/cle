import os
import logging
import subprocess
import struct
from collections import OrderedDict

import elftools

try:
    import claripy
except ImportError:
    claripy = None

__all__ = ('Loader',)

l = logging.getLogger("cle.loader")

class Loader(object):
    """
    The loader loads all the objects and exports an abstraction of the memory of the process. What you see here is an
    address space with loaded and rebased binaries.

    :ivar memory:               The loaded, rebased, and relocated memory of the program.
    :vartype memory:            cle.memory.Clemory
    :ivar main_bin:             The object representing the main binary (i.e., the executable).
    :ivar shared_objects:       A dictionary mapping loaded library names to the objects representing them.
    :ivar all_objects:          A list containing representations of all the different objects loaded.
    :ivar requested_objects:    A set containing the names of all the different shared libraries that were marked as a
                                dependency by somebody.
    :ivar tls_object:           An object dealing with the region of memory allocated for thread-local storage.

    When reference is made to a dictionary of options, it requires a dictionary with zero or more of the following keys:

    - backend :             "elf", "pe", "ida", "blob": which loader backend to use
    - custom_arch :         The archinfo.Arch object to use for the binary
    - custom_base_addr :    The address to rebase the object at
    - custom_entry_point :  The entry point to use for the object

    More keys are defined on a per-backend basis.
    """

    def __init__(self, main_binary, auto_load_libs=True,
                 force_load_libs=None, skip_libs=None,
                 main_opts=None, lib_opts=None, custom_ld_path=None,
                 ignore_import_version_numbers=True, rebase_granularity=0x1000000,
                 except_missing_libs=False, gdb_map=None, gdb_fix=False, aslr=False):
        """
        :param main_binary:         The path to the main binary you're loading, or a file-like object with the binary
                                    in it.

        The following parameters are optional.

        :param auto_load_libs:      Whether to automatically load shared libraries that loaded objects depend on.
        :param force_load_libs:     A list of libraries to load regardless of if they're required by a loaded object.
        :param skip_libs:           A list of libraries to never load, even if they're required by a loaded object.
        :param main_opts:           A dictionary of options to be used loading the main binary.
        :param lib_opts:            A dictionary mapping library names to the dictionaries of options to be used when
                                    loading them.
        :param custom_ld_path:      A list of paths in which we can search for shared libraries.
        :param ignore_import_version_numbers:
                                    Whether libraries with different version numbers in the filename will be considered
                                    equivalent, for example libc.so.6 and libc.so.0
        :param rebase_granularity:  The alignment to use for rebasing shared objects
        :param except_missing_libs: Throw an exception when a shared library can't be found.
        :param gdb_map:             The output of `info proc mappings` or `info sharedlibrary` in gdb. This will be used
                                    to determine the base address of libraries.
        :param gdb_fix:             If `info sharedlibrary` was used, the addresses gdb gives us are in fact the
                                    addresses of the .text sections. We need to fix them to get the real load addresses.
        :param aslr                 Load libraries in symbolic address space.
        """

        if hasattr(main_binary, 'seek') and hasattr(main_binary, 'read'):
            self._main_binary_path = None
            self._main_binary_stream = main_binary
        else:
            self._main_binary_path = os.path.realpath(str(main_binary))
            self._main_binary_stream = None
        self._auto_load_libs = auto_load_libs
        self._unsatisfied_deps = [] if force_load_libs is None else list(force_load_libs)
        self._satisfied_deps = set([] if skip_libs is None else skip_libs)
        self._main_opts = {} if main_opts is None else main_opts
        self._lib_opts = {} if lib_opts is None else lib_opts
        self._custom_ld_path = [] if custom_ld_path is None else custom_ld_path
        self._ignore_import_version_numbers = ignore_import_version_numbers
        self._rebase_granularity = rebase_granularity
        self._except_missing_libs = except_missing_libs
        self._relocated_objects = set()

        self.aslr = aslr
        self.memory = None
        self.main_bin = None
        self.shared_objects = OrderedDict()
        self.all_objects = []
        self.requested_objects = set()
        self.tls_object = None
        self._load_main_binary()

        if gdb_map is not None:
            self._gdb_fix = gdb_fix
            gdb_lib_opts = self._gdb_load_options(gdb_map)
            self._lib_opts = self._merge_opts(gdb_lib_opts, self._lib_opts)

        self._load_dependencies()
        self._load_tls()
        self._perform_reloc(self.main_bin)
        self._finalize_tls()

    def close(self):
        for obj in self.all_objects:
            obj.close()

    def __repr__(self):
        if self._main_binary_stream is None:
            return '<Loaded %s, maps [%#x:%#x]>' % (os.path.basename(self._main_binary_path), self.min_addr(), self.max_addr())
        else:
            return '<Loaded from stream, maps [%#x:%#x]>' % (self.min_addr(), self.max_addr())

    def get_initializers(self):
        """
        Return a list of all the initializers that should be run before execution reaches the entry point, in the order
        they should be run.
        """
        return sum(map(lambda x: x.get_initializers(), self.all_objects), [])

    def get_finalizers(self):
        """
        Return a list of all the finalizers that should be run before the program exits.
        I'm not sure what order they should be run in.
        """
        return sum(map(lambda x: x.get_initializers(), self.all_objects), [])

    @property
    def linux_loader_object(self):
        for obj in self.all_objects:
            if obj.provides is None:
                continue
            if self._is_linux_loader_name(obj.provides) is True:
                return obj
        return None

    @staticmethod
    def _is_linux_loader_name(name):
        """
        ld can have different names such as ld-2.19.so or ld-linux-x86-64.so.2 depending on symlinks and whatnot.
        This determines if `name` is a suitable candidate for ld.
        """
        return 'ld.so' in name or 'ld64.so' in name or 'ld-linux' in name

    def _load_main_binary(self):
        options = dict(self._main_opts)
        options['aslr'] = self.aslr
        self.main_bin = self.load_object(self._main_binary_path
                                            if self._main_binary_stream is None
                                            else self._main_binary_stream,
                                        self._main_opts,
                                        is_main_bin=True)
        self.memory = Clemory(self.main_bin.arch, root=True)
        base_addr = self._main_opts.get('custom_base_addr', None)
        if base_addr is None and self.main_bin.requested_base is not None:
            base_addr = self.main_bin.requested_base
        if base_addr is None and self.main_bin.pic:
            l.warning("The main binary is a position-independent executable. "
                      "It is being loaded with a base address of 0x400000.")
            base_addr = 0x400000
        if base_addr is None:
            base_addr = 0
        self.add_object(self.main_bin, base_addr)

    def _load_dependencies(self):
        while len(self._unsatisfied_deps) > 0:
            dep = self._unsatisfied_deps.pop(0)
            options = {}
            if isinstance(dep, (str, unicode)):
                if os.path.basename(dep) in self._satisfied_deps:
                    continue
                if self._ignore_import_version_numbers and dep.strip('.0123456789') in self._satisfied_deps:
                    continue

                path = self._get_lib_path(dep)

                for path in self._possible_paths(dep):
                    libname = os.path.basename(path)
                    if self.identify_object(path) == 'elf':
                        soname = self._extract_soname(path)
                    else:
                        soname = libname

                    if libname in self._lib_opts.keys():
                        options = dict(self._lib_opts[libname])
                    elif soname in self._lib_opts.keys():
                        options = dict(self._lib_opts[soname])

                    try:
                        options['aslr'] = self.aslr
                        obj = self.load_object(path, options, compatible_with=self.main_bin)
                        break
                    except (CLECompatibilityError, CLEFileNotFoundError):
                        continue
                else:
                    if self._except_missing_libs:
                        raise CLEFileNotFoundError("Could not find shared library: %s" % dep)
                    continue
            elif isinstance(dep, Backend):
                obj = dep
            else:
                raise CLEError("Bad library: %s" % path)

            base_addr = options.get('custom_base_addr', None)
            self.add_object(obj, base_addr)

    @staticmethod
    def load_object(path, options=None, compatible_with=None, is_main_bin=False):
        """
        Load a file with some backend. Try to identify the type of the file to autodetect which backend to use.

        :param str path:            The path to the file to load

        The following parameters are optional.

        :param dict options:        A dictionary of keyword arguments to the backend. Can contain a `backend` key to
                                    force the use of a specific backend
        :param compatiable_with:    Another backend object that this file must be compatible with.
                                    This method will throw a :class:`CLECompatibilityError <cle.errors.CLECompatibilityError>`
                                    if the file at the given path is not compatibile with this parameter.
        :param bool is_main_bin:    Whether this file is the main executable of whatever process we are loading
        """
        # Try to find the filetype of the object. Also detect if you were given a bad filepath
        if options is None:
            options = {}
        try:
            filetype = Loader.identify_object(path)
        except OSError:
            raise CLEFileNotFoundError('File %s does not exist!' % path)

        # Verify that that filetype is acceptable
        if compatible_with is not None and filetype != compatible_with.filetype:
            raise CLECompatibilityError('File %s is not compatible with %s' % (path, compatible_with))

        # Check if the user specified a backend as...
        backend_option = options.get('backend', None)
        if isinstance(backend_option, type) and issubclass(backend_option, Backend):
            # ...an actual backend class
            backends = [backend_option]
        elif backend_option in ALL_BACKENDS:
            # ...the name of a backend class
            backends = [ALL_BACKENDS[backend_option]]
        elif isinstance(backend_option, (list, tuple)):
            # ...a list of backends containing either names or classes
            backends = []
            for backend_option_item in backend_option:
                if isinstance(backend_option_item, type) and issubclass(backend_option_item, Backend):
                    backends.append(backend_option_item)
                elif backend_option_item in ALL_BACKENDS:
                    backends.append(ALL_BACKENDS[backend_option_item])
                else:
                    raise CLEError('Invalid backend: %s' % backend_option_item)
        elif backend_option is None:
            backends = ALL_BACKENDS.values()
        else:
            raise CLEError('Invalid backend: %s' % backend_option)

        backends = filter(lambda x: filetype in x.supported_filetypes, backends)
        if len(backends) == 0:
            raise CLECompatibilityError('No compatible backends specified for filetype %s (file %s)' % (filetype, path))

        for backend in backends:
            try:
                loaded = backend(path, compatible_with=compatible_with, filetype=filetype, is_main_bin=is_main_bin, **options)
                return loaded
            except CLECompatibilityError:
                raise
            except CLEError:
                l.exception("Loading error when loading %s with backend %s", path, backend.__name__)
        raise CLEError("All backends failed loading %s!" % path)

    def get_loader_symbolic_constraints(self):
        if not self.aslr:
            return []
        if not claripy:
            l.error("Please install claripy to get symbolic constraints")
            return []
        outputlist = []
        for obj in self.all_objects:
            #TODO Fix Symbolic for tls whatever
            if obj.aslr and isinstance(obj.rebase_addr_symbolic, claripy.ast.BV):
                outputlist.append(obj.rebase_addr_symbolic == obj.rebase_addr)
        return outputlist

    @staticmethod
    def identify_object(path):
        """
        Returns the filetype of the file `path`. Will be one of the strings in {'elf', 'elfcore', 'pe', 'mach-o',
        'unknown'}.
        """
        if hasattr(path, 'seek') and hasattr(path, 'read'):
            path.seek(0)
            stream = path
            plsclose = False
        else:
            stream = open(path, 'rb')
            plsclose = True

        identstring = stream.read(0x1000)
        stream.seek(0)

        if identstring.startswith('\x7fELF'):
            if elftools.elf.elffile.ELFFile(stream).header['e_type'] == 'ET_CORE':
                if plsclose: stream.close()
                return 'elfcore'
            if plsclose: stream.close()
            return 'elf'
        elif identstring.startswith('MZ') and len(identstring) > 0x40:
            peptr = struct.unpack('I', identstring[0x3c:0x40])[0]
            if peptr < len(identstring) and identstring[peptr:peptr+4] == 'PE\0\0':
                return 'pe'
        elif identstring.startswith('\xfe\xed\xfa\xce') or \
             identstring.startswith('\xfe\xed\xfa\xcf') or \
             identstring.startswith('\xce\xfa\xed\xfe') or \
             identstring.startswith('\xcf\xfa\xed\xfe'):
            return 'mach-o'
        elif identstring.startswith('\x7fCGC'):
            return 'cgc'
        return 'unknown'

    def add_object(self, obj, base_addr=None):
        """
        Add object `obj` to the memory map, rebased at `base_addr`. If `base_addr` is None CLE will pick a safe one.
        Registers all its dependencies.
        """

        if self._auto_load_libs:
            self._unsatisfied_deps += obj.deps
        self.requested_objects.update(obj.deps)

        if obj.provides is not None:
            self._satisfied_deps.add(obj.provides)
            if self._ignore_import_version_numbers:
                self._satisfied_deps.add(obj.provides.strip('.0123456789'))

        obj.rebase_addr = 0
        obj_offset = obj.get_min_addr()
        obj_size = obj.get_max_addr() - obj_offset

        if base_addr is not None and self._is_range_free(base_addr + obj_offset, obj_size):
            pass
        elif obj.requested_base is not None and self._is_range_free(obj.requested_base + obj_offset, obj_size):
            base_addr = obj.requested_base
        else:
            base_addr = self._get_safe_rebase_addr()

        self.all_objects.append(obj)
        if obj.provides is not None:
            self.shared_objects[obj.provides] = obj

        l.info("[Rebasing %s @%#x]", obj.binary, base_addr)
        self.memory.add_backer(base_addr, obj.memory)
        obj.rebase_addr = base_addr

    def _is_range_free(self, addr, size):
        for o in self.all_objects:
            if (addr >= o.get_min_addr() and addr < o.get_max_addr()) or \
               (o.get_min_addr() >= addr and o.get_min_addr() < addr + size):
                return False
        return True


    def _possible_paths(self, path):
        if os.path.exists(path): yield path
        dirs = []                   # if we say dirs = blah, we modify the original
        dirs += self._custom_ld_path
        if self._main_binary_path is not None:
            dirs += [os.path.dirname(self._main_binary_path)]
        dirs += self.main_bin.arch.library_search_path()
        for libdir in dirs:
            fullpath = os.path.realpath(os.path.join(libdir, path))
            if os.path.exists(fullpath): yield fullpath
            if self._ignore_import_version_numbers:
                try:
                    for libname in os.listdir(libdir):
                        if libname.strip('.0123456789') == path.strip('.0123456789'):
                            yield os.path.realpath(os.path.join(libdir, libname))
                except (IOError, OSError): pass

    def relocate(self):
        """
        Attemts to resolve all yet-unresolved relocations in all loaded objects.
        It is appropriate to call this repeatedly.
        """

        self._relocated_objects = set()
        for obj in self.all_objects:
            self._perform_reloc(obj)

    def _perform_reloc(self, obj):
        if id(obj) in self._relocated_objects:
            return
        self._relocated_objects.add(id(obj))

        dep_objs = [self.shared_objects[dep_name] for dep_name in obj.deps if dep_name in self.shared_objects]
        for dep_obj in dep_objs:
            self._perform_reloc(dep_obj)

        if isinstance(obj, (MetaELF, PE)):
            for reloc in obj.relocs:
                if not reloc.resolved:
                    reloc.relocate(([self.main_bin] if self.main_bin is not obj else []) + dep_objs + [obj])

    def provide_symbol(self, owner, name, offset, size=0, sym_type=None):
        if sym_type is None: sym_type = Symbol.TYPE_FUNCTION
        newsymbol = Symbol(owner, name, offset, size, sym_type)
        newsymbol.is_export = True
        owner._symbol_cache[name] = newsymbol
        solist = [owner]

        for obj in self.all_objects:
            if isinstance(obj, (MetaELF, PE)):
                for reloc in obj.relocs:
                    if reloc.symbol and reloc.symbol.name == name:
                        reloc.relocate(solist, bypass_compatibility=True)


    def _get_safe_rebase_addr(self):
        """
        Get a "safe" rebase addr, i.e., that won't overlap with already loaded stuff. This is used as a fallback when we
        cannot use LD to tell use where to load a binary object. It is also a workaround to IDA crashes when we try to
        rebase binaries at too high addresses.
        """
        granularity = self._rebase_granularity
        return self.max_addr() + (granularity - self.max_addr() % granularity)

    def _load_tls(self):
        """
        Set up an object to store TLS data in.
        """
        elf_modules = []
        pe_modules = []

        for obj in self.all_objects:
            if isinstance(obj, MetaELF) and obj.tls_used:
                elf_modules.append(obj)
            elif isinstance(obj, PE) and obj.tls_used:
                pe_modules.append(obj)
        num_elf_modules = len(elf_modules)
        num_pe_modules = len(pe_modules)

        # TODO: This assert ensures that we have either ELF or PE modules, but not both.
        # Do we need to handle the case where we have both ELF and PE modules?
        assert num_elf_modules != num_pe_modules or num_elf_modules == 0 or num_pe_modules == 0
        if len(elf_modules) > 0:
            self.tls_object = ELFTLSObj(elf_modules)
        elif len(pe_modules) > 0:
            self.tls_object = PETLSObj(pe_modules)

        if self.tls_object:
            self.add_object(self.tls_object)

    def _finalize_tls(self):
        """
        Lay out the TLS initialization images into memory.
        """
        if self.tls_object is not None:
            self.tls_object.finalize()

    def addr_belongs_to_object(self, addr):
        for obj in self.all_objects:
            if not (addr >= obj.get_min_addr() and addr < obj.get_max_addr()):
                continue

            if isinstance(obj.memory, str):
                return obj

            elif isinstance(obj.memory, Clemory):
                if addr - obj.rebase_addr in obj.memory:
                    return obj

            else:
                raise CLEError('Unsupported memory type %s' % type(obj.memory))

        return None

    def whats_at(self, addr):
        """
        Tells you what's at `addr` in terms of the offset in one of the loaded binary objects.
        """
        o = self.addr_belongs_to_object(addr)

        if o is None:
            return None

        off = addr - o.rebase_addr
        nameof = 'main binary' if o is self.main_bin else o.provides

        if isinstance(o, ELF):
            if addr in o.plt.values():
                for k,v in o.plt.iteritems():
                    if v == addr:
                        return  "PLT stub of %s in %s (offset %#x)" % (k, nameof, off)

            if off in o.symbols_by_addr:
                name = o.symbols_by_addr[off].name
                return "%s (offset %#x) in %s" % (name, off, nameof)

        return "Offset %#x in %s" % (off, nameof)

    def max_addr(self):
        """
        The maximum address loaded as part of any loaded object (i.e., the whole address space).
        """
        return max(map(lambda x: x.get_max_addr(), self.all_objects))

    def min_addr(self):
        """
        The minimum address loaded as part of any loaded object (i.e., the whole address space).
        """
        return min(map(lambda x: x.get_min_addr(), self.all_objects))

    # Search functions

    def find_symbol_name(self, addr):
        """
        Return the name of the function starting at `addr`.
        """
        for so in self.all_objects:
            if addr - so.rebase_addr in so.symbols_by_addr:
                return so.symbols_by_addr[addr - so.rebase_addr].name
        return None

    def find_plt_stub_name(self, addr):
        """
        Return the name of the PLT stub starting at `addr`.
        """
        for so in self.all_objects:
            if isinstance(so, MetaELF):
                if addr in so.reverse_plt:
                    return so.reverse_plt[addr]
        return None

    def find_module_name(self, addr):
        """
        Return the name of the loaded module containing `addr`.
        """
        for o in self.all_objects:
            # The Elf class only works with static non-relocated addresses
            if o.contains_addr(addr - o.rebase_addr):
                return o.provides

    def find_symbol_got_entry(self, symbol):
        """
        Look for the address of a GOT entry for `symbol`.

        :returns:   The address of the symbol if found, None otherwise.
        """
        if isinstance(self.main_bin, IDABin):
            if symbol in self.main_bin.imports:
                return self.main_bin.imports[symbol]
        elif isinstance(self.main_bin, ELF):
            if symbol in self.main_bin.jmprel:
                return self.main_bin.jmprel[symbol].addr

    def _ld_so_addr(self):
        """
        Use LD_AUDIT to find object dependencies and relocation addresses.
        """

        qemu = 'qemu-%s' % self.main_bin.arch.qemu_name
        env_p = os.getenv("VIRTUAL_ENV", "/")
        bin_p = os.path.join(env_p, "local/lib", self.main_bin.arch.name.lower())

        # Our LD_AUDIT shared object
        ld_audit_obj = os.path.join(bin_p, "cle_ld_audit.so")

        #LD_LIBRARY_PATH
        ld_path = os.getenv("LD_LIBRARY_PATH")
        if ld_path is None:
            ld_path = bin_p
        else:
            ld_path = ld_path + ":" + bin_p

        cross_libs = self.main_bin.arch.lib_paths
        if self.main_bin.arch.name in ('AMD64', 'X86'):
            ld_libs = self.main_bin.arch.lib_paths
        elif self.main_bin.arch.name == 'PPC64':
            ld_libs = map(lambda x: x + 'lib64/', self.main_bin.arch.lib_paths)
        else:
            ld_libs = map(lambda x: x + 'lib/', self.main_bin.arch.lib_paths)
        ld_libs = ':'.join(ld_libs)
        ld_path = ld_path + ":" + ld_libs

        # Make LD look for custom libraries in the right place
        if self._custom_ld_path is not None:
            ld_path = self._custom_ld_path + ":" + ld_path

        var = "LD_LIBRARY_PATH=%s,LD_AUDIT=%s,LD_BIND_NOW=yes" % (ld_path, ld_audit_obj)

        # Let's work on a copy of the binary
        binary = self._binary_screwup_copy(self._main_binary_path)

        #LD_AUDIT's output
        log = "./ld_audit.out"

        cmd = [qemu, "-strace", "-L", cross_libs, "-E", var, binary]
        s = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # Check stderr for library loading issues
        err = s.stderr.readlines()
        msg = "cannot open shared object file"

        deps = self.main_bin.deps

        for dep in deps:
            for str_e in err:
                if dep in str_e and msg in str_e:
                    l.error("LD could not find dependency %s.", dep)
                    l.error("GNU LD will stop looking for libraries to load if "
                            "it doesn't find one of them.")
                    #self.ld_missing_libs.append(dep)
                    break

        s.communicate()

        # Our LD_AUDIT library is supposed to generate a log file.
        # If not we're in trouble
        if os.path.exists(log):
            libs = {}
            with open(log, 'r') as f:
                for i in f.readlines():
                    lib = i.split(",")
                    if lib[0] == "LIB":
                        libs[lib[1]] = int(lib[2].strip(), 16)
            l.debug("---")
            for o, a in libs.iteritems():
                l.debug(" -> Dependency: %s @ %#x)", o, a)

            l.debug("---")
            os.remove(log)
            return libs

        else:

            l.error("Could not find library dependencies using ld."
                    " The log file '%s' does not exist, did qemu fail ? Try to run "
                    "`%s` manually to check", log, " ".join(cmd))
            raise CLEOperationError("Could not find library dependencies using ld.")

    def _binary_screwup_copy(self, path):
        """
        When LD_AUDIT cannot load CLE's auditing library, it unfortunately falls back to executing the target, which we
        don't want ! This is a problem specific to GNU LD, we can't fix this.

        This is a simple hack to work around it: set the address of the entry point to 0 in the program header
        This will cause the main binary to segfault if executed.
        """

        # Let's work on a copy of the main binary
        copy = self._make_tmp_copy(path, suffix=".screwed")
        with open(copy, 'r+b') as f:
            # Looking at elf.h, we can see that the the entry point's
            # definition is always at the same place for all architectures.
            off = 0x18
            f.seek(off)
            count = self.main_bin.arch.bits / 8

            # Set the entry point to address 0
            screw_char = "\x00"
            screw = screw_char * count
            f.write(screw)
            return copy

    @staticmethod
    def _make_tmp_copy(path, suffix=None):
        """
        Makes a copy of obj into CLE's tmp directory.
        """
        if not os.path.exists('/tmp/cle'):
            os.mkdir('/tmp/cle')

        if hasattr(path, 'seek') and hasattr(path, 'read'):
            stream = path
        else:
            try:
                stream = open(path, 'rb')
            except IOError:
                raise CLEFileNotFoundError("File %s does not exist :(. Please check that the"
                                           " path is correct" % path)
        bn = os.urandom(5).encode('hex')
        if suffix is not None:
            bn += suffix
        dest = os.path.join('/tmp/cle', bn)
        l.info("\t -> copy obj %s to %s", path, dest)

        with open(dest, 'wb') as dest_stream:
            while True:
                dat = stream.read(1024*1024)
                if len(dat) == 0:
                    break
                dest_stream.write(dat)

        return dest

    @staticmethod
    def _parse_gdb_map(gdb_map):
        """
        Parser for gdb's ``info proc mappings``, or ``info sharedlibs``, or custom
        mapping file of the form base_addr : /path/to/lib.
        """
        if os.path.exists(gdb_map):
            with open(gdb_map, 'rb') as f:
                data = f.readlines()
            gmap = {}
            for line in data:
                line_items = line.split()
                if line == '\n':
                    continue
                # Get rid of all metadata, just extract lines containing addresses
                if "0x" not in line_items[0]:
                    continue
                elif "linux-vdso" in line_items[-1]:
                    continue
                addr, objfile = int(line_items[0], 16), line_items[-1].strip()

                # Get the smallest address of each libs' mappings
                try:
                    gmap[objfile] = min(gmap[objfile], addr)
                except KeyError:
                    gmap[objfile] = addr
            return gmap

    def _gdb_load_options(self, gdb_map_path):
        """
        Generate library options from a gdb proc mapping.
        """
        lib_opts = {}
        gmap = self._parse_gdb_map(gdb_map_path)

        # Find lib names
        #libnames = filter(lambda n: '.so' in n, gmap.keys())

        # Find base addr for each lib (each lib is mapped to several segments,
        # we take the segment that is loaded at the smallest address).
        for lib, addr in gmap.items():
            if not ".so" in lib:
                continue
            if not os.path.exists(lib):
                lib = self._get_lib_path(lib)

            soname = self._extract_soname(lib)

            # address of .text -> base address of the library
            if self._gdb_fix:
                addr = addr - self._get_text_offset(lib)

            l.info("gdb_plugin: mapped %s to %#x", lib, addr)
            lib_opts[soname] = {"custom_base_addr":addr}
        return lib_opts

    @staticmethod
    def _get_text_offset(path):
        """
        Offset of .text in the binary.
        """
        if not os.path.exists(path):
            raise CLEError("Path %s does not exist" % path)

        with open(path, 'rb') as f:
            e = elftools.elf.elffile.ELFFile(f)
            return e.get_section_by_name(".text").header.sh_offset

    @staticmethod
    def _extract_soname(path):
        """
        Extracts the soname from the ELF binary at `path`.
        """
        if not os.path.exists(path):
            raise CLEError("Path %s does not exist" % path)

        with open(path, 'rb') as f:
            try:
                e = elftools.elf.elffile.ELFFile(f)
                dyn = e.get_section_by_name('.dynamic')
                soname = [ x.soname for x in list(dyn.iter_tags()) if x.entry.d_tag == 'DT_SONAME']
                if not soname:
                    return os.path.basename(path)
                return soname[0]
            except elftools.common.exceptions.ELFError:
                return None

    def _check_compatibility(self, path):
        """
        This checks whether the object at `path` is binary compatible with the main binary.
        """
        try:
            filetype = Loader.identify_object(path)
        except OSError:
            raise CLEFileNotFoundError('File %s does not exist!' % path)

        return self.main_bin.filetype == filetype

    def _get_lib_path(self, libname):
        """
        Get a path for `libname`. We pick the first plausible candidate that is binary compatible.
        """
        # Valid path
        if os.path.exists(libname) and self._check_compatibility(libname):
            return libname

        # Wrong path and not a lib name
        elif not os.path.exists(libname) and libname != os.path.basename(libname):
            raise CLEFileNotFoundError("Invalid path or soname: %s" % libname)
        paths = list(self._possible_paths(os.path.basename(libname)))
        for p in paths:
            if self._check_compatibility(p):
                return p

    @staticmethod
    def _merge_opts(opts, dest):
        """
        Return a new dict corresponding to merging *opts* into *dest*. This makes sure we don't override previous
        options.
        """
        for k,v in opts.iteritems():
            if k in dest and v in dest[k]:
                raise CLEError("%s/%s is overriden by gdb's" % (k,v))
        return dict(opts.items() + dest.items())

    @property
    def all_elf_objects(self):
        return [o for o in self.all_objects if isinstance(o, MetaELF)]

    def perform_irelative_relocs(self, resolver_func):
        for obj in self.all_objects:
            for resolver, dest in obj.irelatives:
                val = resolver_func(resolver)
                if val is not None:
                    obj.memory.write_addr_at(dest, val)

from .errors import CLEError, CLEOperationError, CLEFileNotFoundError, CLECompatibilityError
from .memory import Clemory
from .tls import ELFTLSObj, PETLSObj
from .backends import IDABin, MetaELF, ELF, PE, ALL_BACKENDS, Backend, Symbol
