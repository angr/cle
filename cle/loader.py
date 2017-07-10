import os, sys
import logging
from collections import OrderedDict

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

        - backend :             "elf", "pe", "ida", "blob" : which loader backend to use
        - custom_arch :         The archinfo.Arch object to use for the binary
        - custom_base_addr :    The address to rebase the object at
        - custom_entry_point :  The entry point to use for the object

    More keys are defined on a per-backend basis.
    """

    MAIN_OPTIONS = { 'backend', 'custom_arch', 'custom_base_addr', 'custom_entry_point',
                     # Blob
                     'custom_offset', 'segments',
                     }

    def __init__(self, main_binary, auto_load_libs=True,
                 force_load_libs=None, skip_libs=None,
                 main_opts=None, lib_opts=None, custom_ld_path=None,
                 ignore_import_version_numbers=True, rebase_granularity=0x1000000,
                 except_missing_libs=False, gdb_map=None, gdb_fix=False, aslr=False,
                 page_size=0x1000):
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
        :param gdb_map:             The output of ``info proc mappings`` or ``info sharedlibrary`` in gdb. This will
                                    be used to determine the base address of libraries.
        :param gdb_fix:             If ``info sharedlibrary`` was used, the addresses gdb gives us are in fact the
                                    addresses of the .text sections. We need to fix them to get the real load addresses.
        :param aslr:                Load libraries in symbolic address space.
        :param page_size:           The granularity with which data is mapped into memory. Set to 1 if you are working
                                    in a non-paged environment.
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
        self._custom_ld_path = [] if custom_ld_path is None else [custom_ld_path] if type(custom_ld_path) in (str, unicode) else custom_ld_path
        self._ignore_import_version_numbers = ignore_import_version_numbers
        self._rebase_granularity = rebase_granularity
        self._except_missing_libs = except_missing_libs
        self._relocated_objects = set()

        self._sanitize_main_opts(self._main_opts)

        self.aslr = aslr
        self.page_size = page_size
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

    def _sanitize_main_opts(self, main_opts):

        if not main_opts:
            return

        for k in main_opts.iterkeys():
            if k not in self.MAIN_OPTIONS:
                guess = None
                if k == 'custom_base_address':
                    # some people never get it right
                    guess = 'custom_base_addr'

                if not guess:
                    raise CLEError('Unsupported option "%s" in main_opts.' % k)
                else:
                    raise CLEError('Unsupported option "%s" in main_opts. Do you mean "%s"?' % (k, guess))

    def _load_main_binary(self):
        options = dict(self._main_opts)
        options['aslr'] = self.aslr
        self.main_bin = self.load_object(self._main_binary_path
                                            if self._main_binary_stream is None
                                            else self._main_binary_stream,
                                        is_main_bin=True)
        self.memory = Clemory(self.main_bin.arch, root=True)
        self.add_object(self.main_bin)

    def _load_dependencies(self):
        while len(self._unsatisfied_deps) > 0:
            dep = self._unsatisfied_deps.pop(0)
            if isinstance(dep, (str, unicode)):
                if os.path.basename(dep) in self._satisfied_deps:
                    continue
                if self._ignore_import_version_numbers and dep.strip('.0123456789') in self._satisfied_deps:
                    continue

                path = self._get_lib_path(dep)

                for path in self._possible_paths(dep):
                    try:
                        obj = self.load_object(path, compatible_with=self.main_bin)
                        break
                    except (CLECompatibilityError, CLEFileNotFoundError):
                        continue
                else:
                    if self._except_missing_libs:
                        raise CLEFileNotFoundError("Could not find shared library: %s" % dep)
                    continue
            elif hasattr(dep, 'read') and hasattr(dep, 'seek'):
                obj = self.load_object(dep, compatible_with=self.main_bin)
            elif isinstance(dep, Backend):
                obj = dep
            else:
                raise CLEError("Bad library: %s" % path)

            self.add_object(obj)

    def load_object(self, path, compatible_with=None, is_main_bin=False, backend=None, **kwargs):
        """
        Load a file with some backend. Try to identify the type of the file to autodetect which backend to use.

        :param str path:            The path to the file to load

        The following parameters are optional.

        :param compatiable_with:    Another backend object that this file must be compatible with.
                                    This method will throw a :class:`CLECompatibilityError <cle.errors.CLECompatibilityError>`
                                    if the file at the given path is not compatibile with this parameter.
        :param bool is_main_bin:    Whether this file is the main executable of whatever process we are loading
        :param backend:             The specific backend to use.
        :param kwargs:              Any additional keyword args will be passed to the backend. These will be augmented
                                    (overridden) by any options specified in ``lib_opts`` or ``main_opts``.
        """
        # most of the complexity of this function is the horrible complexity of the options system
        # first we grab as many options as we can right now
        if is_main_bin:
            kwargs.update(self._main_opts)
        else:
            libname = os.path.basename(path) if isinstance(path, (str, unicode)) else None
            if libname is not None and libname in self._lib_opts:
                kwargs.update(self._lib_opts[libname])

        # the 'backend' option is special - it must be dealt with now
        # make a first attempt to find the backend to use
        if 'backend' in kwargs:
            backend = kwargs.pop('backend')
        backend_cls = self._backend_resolver(backend)
        if backend_cls is None:
            backend_cls = self.identify_object(path)

        # now that we have at least some backend, we can grab the soname and use that to get some more options
        if not is_main_bin:
            soname = backend_cls.extract_soname(path)
            if soname is not None and soname in self._lib_opts:
                kwargs.update(self._lib_opts[soname])

        # if this new set of arguments specified a backend (???) we want to use that instead
        if 'backend' in kwargs:
            backend_cls = self._backend_resolver(kwargs.pop('backend'), backend_cls)

        # do the load!!!
        return backend_cls(path, compatible_with=compatible_with, is_main_bin=is_main_bin, loader=self, **kwargs)

    @staticmethod
    def _backend_resolver(backend, default=None):
        if isinstance(backend, type) and issubclass(backend, Backend):
            return backend
        elif backend in ALL_BACKENDS:
            return ALL_BACKENDS[backend]
        elif backend is None:
            return default
        else:
            raise CLEError('Invalid backend: %s' % backend)

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
        Returns the correct loader for the file at `path`.
        Returns None if it's a blob or some unknown type.
        TODO: Implement some binwalk-like thing to carve up blobs aotmatically
        """

        with stream_or_path(path) as stream:
            for rear in ALL_BACKENDS.values():
                if rear.is_compatible(stream):
                    return rear

        raise CLECompatibilityError("Unable to find a loader backend for this binary.  Perhaps try the 'blob' loader?")

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
        elif obj._custom_base_addr is not None and self._is_range_free(obj._custom_base_addr + obj_offset, obj_size):
            base_addr = obj._custom_base_addr
        elif obj.requested_base is not None and self._is_range_free(obj.requested_base + obj_offset, obj_size):
            base_addr = obj.requested_base
        elif not obj.is_main_bin:
            base_addr = self._get_safe_rebase_addr()
        elif self.main_bin.pic:
            l.warning("The main binary is a position-independent executable. "
                      "It is being loaded with a base address of 0x400000.")
            base_addr = 0x400000
        else:
            base_addr = 0

        self.all_objects.append(obj)
        if obj.provides is not None:
            self.shared_objects[obj.provides] = obj

        l.info("Rebasing %s at %#x", obj.binary, base_addr)
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
        if sys.platform == 'win32':
            dirs.append(os.path.join(os.environ['SYSTEMROOT'], 'System32'))
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
        return self.provide_symbol_batch(owner, {name: (offset, size, sym_type)})

    def provide_symbol_batch(self, owner, provisions):
        symbols = {}
        for name, (offset, size, sym_type) in provisions.iteritems():
            if sym_type is None: sym_type = Symbol.TYPE_FUNCTION
            newsymbol = Symbol(owner, name, offset, size, sym_type)
            newsymbol.is_export = True
            owner._symbol_cache[name] = newsymbol
            symbols[name] = newsymbol

        solist = [owner]

        for obj in self.all_objects:
            if isinstance(obj, (MetaELF, PE)):
                for reloc in obj.relocs:
                    if reloc.symbol and reloc.symbol.name in symbols:
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

    def find_symbol(self, name):
        """
        Search for the symbol with the given name. Return a :class:`cle.backends.Symbol` object if found, None
        otherwise.
        """
        for so in self.all_objects:
            sym = so.get_symbol(name)
            if sym is None:
                continue

            if sym.is_import:
                if sym.resolvedby is not None:
                    return sym.resolvedby
            else:
                return sym

        return None

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
                elif any(s in line_items[-1] for s in ("linux-vdso", "[vdso]")):
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

            soname = MetaELF.extract_soname(lib)

            # address of .text -> base address of the library
            if self._gdb_fix:
                addr = addr - MetaELF.get_text_offset(lib)

            l.info("gdb_plugin: mapped %s to %#x", lib, addr)
            lib_opts[soname] = {"custom_base_addr":addr}
        return lib_opts

    def _check_compatibility(self, path):
        """
        This checks whether the object at `path` is binary compatible with the main binary.
        """
        try:
            backend = Loader.identify_object(path)
        except OSError:
            raise CLEFileNotFoundError('File %s does not exist!' % path)
        except CLECompatibilityError:
            return False
        return type(self.main_bin) == backend

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

from .errors import CLEError, CLEFileNotFoundError, CLECompatibilityError
from .memory import Clemory
from .tls import ELFTLSObj, PETLSObj
from .backends import IDABin, MetaELF, ELF, PE, ALL_BACKENDS, Backend, Symbol
from .utils import stream_or_path
