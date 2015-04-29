#!/usr/bin/env python

# from ctypes import *
import os
import logging
import shutil
import subprocess

from .elf import ELF
from .metaelf import MetaELF
from .cleextractor import CLEExtractor
from .pe import Pe
from .idabin import IdaBin
from .blob import Blob
from .archinfo import ArchInfo
from .clexception import CLException, UnknownFormatException
from .memory import Clemory

# import platform
# import binascii

l = logging.getLogger("cle.ld")

# FIXME list
#     1)  add support for per-library backend (right now, it all depends on the
#         global flag ida_main, i.e., the main binary's backend.
#     2)  Smart fallback: if no backend was specified and it the binary is NOT
#         elf, fall back to blob

class Ld(object):
    """ CLE ELF loader
    The loader loads all the objects and exports an abstraction of the memory of
    the process. What you see here is an address space with loaded and rebased
    binaries.
    """

    def __init__(self, main_binary, auto_load_libs=True,
                 force_load_libs=None, skip_libs=None,
                 main_opts=None, lib_opts=None, custom_ld_path=None,
                 ignore_import_version_numbers=True, rebase_granularity=0x1000000):

        self._main_binary_path = os.path.realpath(str(main_binary))
        self._auto_load_libs = auto_load_libs
        self._unsatisfied_deps = [] if force_load_libs is None else force_load_libs
        self._satisfied_deps = set([] if skip_libs is None else skip_libs)
        self._main_opts = {} if main_opts is None else main_opts
        self._lib_opts = {} if lib_opts is None else lib_opts
        self._custom_ld_path = [] if custom_ld_path is None else custom_ld_path
        self._ignore_import_version_numbers = ignore_import_version_numbers
        self._rebase_granularity = rebase_granularity

        # These are all the class variables of Ld
        # Please add new stuff here along with a description :)

        self.memory = None          # The loaded, rebased, and relocated memory of the program
        self.main_bin = None        # The main binary (i.e., the executable)
        self.shared_objects = {}    # Contains autodetected libraries (CLE binaries)
        self.all_objects = []       # all the different objects loaded
        self.requested_objects = set()

        self._load_main_binary()
        self._load_dependencies()
        self._perform_reloc()
        if isinstance(self.main_bin, IdaBin):
            self.ida_sync_mem()

    def _load_main_binary(self):
        base_addr = self._main_opts.get('custom_base_addr', 0)
        self.main_bin = self._load_object(self._main_binary_path, self._main_opts)
        self.memory = Clemory(self.main_bin.archinfo)
        self._rebase_obj(base_addr, self.main_bin)

    def _load_dependencies(self):
        while len(self._unsatisfied_deps) > 0:
            dep = self._unsatisfied_deps.pop(0)
            if dep in self._satisfied_deps:
                continue
            path = self._resolve_path(dep)
            if not path:
                continue
            libname = os.path.basename(path)
            options = self._lib_opts.get(libname, {})
            base_addr = options.get('custom_base_addr', None)
            if base_addr is None:
                base_addr = self._get_safe_rebase_addr()
            obj = self._load_object(path, options)
            self.shared_objects[obj.soname] = obj
            self._rebase_obj(base_addr, obj)

    def _load_object(self, path, options):
        backend = options.get('backend', 'elf')
        if backend == 'elf':
            obj = ELF(path, **options)
        elif backend == 'cleextract':
            obj = CLEExtractor(path, **options)
        elif backend == 'ida':
            obj = IdaBin(path, **options)
        elif backend == 'pe':
            obj = Pe(path, **options)
        elif backend == 'blob':
            obj = Blob(path, **options)
        else:
            raise CLException('Invalid backend: %s' % backend)

        if self._auto_load_libs:
            self._unsatisfied_deps += obj.deps
        self.requested_objects.update(obj.deps)
        self._satisfied_deps.add(path)
        self._satisfied_deps.add(os.path.basename(path))
        self._satisfied_deps.add(os.path.basename(path).strip('.0123456789'))
        self.all_objects.append(obj)
        return obj

    def _resolve_path(self, path):
        if '/' in path:
            if self._check_lib(path):
                return path
        else:
            if self._check_lib(os.path.realpath(path)):
                return os.path.realpath(path)
            if self._check_lib(os.path.join(os.path.basename(self._main_binary_path), path)):
                return os.path.join(os.path.basename(self._main_binary_path), path)
            loc = []
            loc += self._custom_ld_path
            loc += self.main_bin.archinfo._arch_paths()
            # Dangerous, only ok if the hosts sytem's is the same as the target
            #loc.append(os.getenv("LD_LIBRARY_PATH"))

            l.debug("Searching for SO %s in %s", path, str(loc))
            # TODO: Figure out how to get this to not loop in recursive filesystem structures
            for ld_path in loc:
                for s_path, _, files in os.walk(ld_path, followlinks=True):
                    sopath = os.path.join(s_path, path)
                    if path in files and self._check_lib(sopath):
                        return sopath
                    elif self._ignore_import_version_numbers:
                        for filename in files:
                            if filename.startswith(path):
                                sopath = os.path.join(s_path, filename)
                                l.debug("-->Found with version number: %s", path)
                                if self._check_lib(sopath):
                                    return sopath

    def _perform_reloc(self):
        for i, obj in enumerate(self.all_objects):
            obj.tls_module_id = i
            if isinstance(obj, IdaBin):
                self._resolve_imports_ida(obj)
            elif isinstance(obj, Pe):
                pass
            elif isinstance(obj, MetaELF):
                for reloc in obj.relocs:
                    reloc.relocate(self.all_objects)

    def _rebase_obj(self, base, obj):
        """ Relocate a shared objet given a base address
        We actually copy the local memory of the object at the new computed
        address in the "main memory" """

        if isinstance(obj, IdaBin):
            obj.rebase(base)
            return
        l.info("[Rebasing %s @0x%x]", os.path.basename(obj.binary), base)
        self.memory.add_backer(base, obj.memory)
        obj.rebase_addr = base

    def _get_safe_rebase_addr(self):
        """
        Get a "safe" rebase addr, i.e., that won't overlap with already loaded stuff.
        This is used as a fallback when we cannot use LD to tell use where to load
        a binary object. It is also a workaround to IDA crashes when we try to
        rebase binaries at too high addresses.
        """
        granularity = self._rebase_granularity
        return self.max_addr() + (granularity - self.max_addr() % granularity)

    def ida_sync_mem(self):
        """
            TODO: be smarter, and add a flag to IdaBin to toggle resync
        """
        objs = []
        for i in self.all_objects:
            if isinstance(i, IdaBin):
                objs.append(i)
            else:
                l.warning("Not syncing memory for %s, not IDA backed", i.binary)

        for o in objs:
            l.info("**SLOW**: Copy IDA's memory to Ld's memory (%s)", o.binary)
            self.memory.update_backer(o.rebase_addr, o.memory)

    def addr_belongs_to_object(self, addr):
        for obj in self.all_objects:
            if addr - obj.rebase_addr in obj.memory:
                return obj

    def addr_is_ida_mapped(self, addr):
        """ Is the object mapping @addr an instance of IdaBin ?
        """
        return isinstance(IdaBin, self.addr_belongs_to_object(addr))

    def addr_is_mapped(self, addr):
        """ Is addr mapped at all ?
        """
        return self.addr_belongs_to_object(addr) is not None

    def max_addr(self):
        """ The maximum address loaded as part of any loaded object
        (i.e., the whole address space)
        """
        return max(map(lambda x: x.get_max_addr() + x.rebase_addr, self.all_objects))

    def min_addr(self):
        """ The minimum address loaded as part of any loaded object
        i.e., the whole address space)
        """
        return min(map(lambda x: x.get_min_addr() + x.rebase_addr, self.all_objects))

    def override_got_entry(self, symbol, newaddr, obj):
        """ This overrides the address of the function defined by @symbol with
        the new address @newaddr, inside the GOT of object @obj.
        This is used to call simprocedures instead of actual code """

        if symbol not in obj.imports:
            l.debug("Could not override the address of symbol %s: symbol entry not "
                    "found in GOT", symbol)
            return False

        self.memory.write_addr_at(obj.imports[symbol].rebased_addr, newaddr)
        return True

    # Search functions

    def find_symbol_name(self, addr):
        """ Return the name of the function starting at addr.
        """
        for so in self.all_objects:
            if addr - so.rebase_addr in so.symbols_by_addr:
                return so.symbols_by_addr[addr - so.rebase_addr].name
        return None

    def guess_function_name(self, addr):
        """
        Try to guess the name of the function at @addr
        WARNING: this is approximate
        """
        for o in self.all_objects:
            name = o.guess_function_name(addr)
            if name is not None:
                return name

    def find_module_name(self, addr):
        for o in self.all_objects:
            # The Elf class only works with static non-relocated addresses
            if o.contains_addr(addr - o.rebase_addr):
                return os.path.basename(o.binary)

    def find_symbol_got_entry(self, symbol):
        """ Look for the address of a GOT entry for symbol @symbol.
        If found, return the address, otherwise, return None
        """
        if isinstance(self.main_bin, IdaBin):
            if symbol in self.main_bin.imports:
                return self.main_bin.imports[symbol]
        elif isinstance(self.main_bin, ELF):
            if symbol in self.main_bin.jmprel:
                return self.main_bin.jmprel[symbol].addr

    def _ld_so_addr(self):
        """ Use LD_AUDIT to find object dependencies and relocation addresses"""

        qemu = self.main_bin.archinfo.get_qemu_cmd()
        env_p = os.getenv("VIRTUAL_ENV", "/")
        bin_p = os.path.join(env_p, "local/lib", self.main_bin.archinfo.get_unique_name())

        # Our LD_AUDIT shared object
        ld_audit_obj = os.path.join(bin_p, "cle_ld_audit.so")

        #LD_LIBRARY_PATH
        ld_path = os.getenv("LD_LIBRARY_PATH")
        if ld_path == None:
            ld_path = bin_p
        else:
            ld_path = ld_path + ":" + bin_p

        cross_libs = self.main_bin.archinfo.get_cross_library_path()
        ld_libs = self.main_bin.archinfo.get_cross_ld_path()
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
            f = open(log, 'r')
            for i in f.readlines():
                lib = i.split(",")
                if lib[0] == "LIB":
                    libs[lib[1]] = int(lib[2].strip(), 16)
            f.close()
            l.debug("---")
            for o, a in libs.iteritems():
                l.debug(" -> Dependency: %s @ 0x%x)", o, a)

            l.debug("---")
            os.remove(log)
            return libs

        else:

            l.error("Could not find library dependencies using ld."
                    " The log file '%s' does not exist, did qemu fail ? Try to run "
                    "`%s` manually to check", log, " ".join(cmd))
            raise CLException("Could not find library dependencies using ld.")

    def _binary_screwup_copy(self, path):
        """
        When LD_AUDIT cannot load CLE's auditing library, it unfortunately falls
        back to executing the target, which we don't want ! This is a problem
        specific to GNU LD, we can't fix this.

        This is a simple hack to work around it: set the address of the entry
        point to 0 in the program header
        This will cause the main binary to segfault if executed.
        """

        # Let's work on a copy of the main binary
        copy = self._make_tmp_copy(path, suffix=".screwed")
        f = open(copy, 'r+')

        # Looking at elf.h, we can see that the the entry point's
        # definition is always at the same place for all architectures.
        off = 0x18
        f.seek(off)
        count = self.main_bin.archinfo.bits / 8

        # Set the entry point to address 0
        screw_char = "\x00"
        screw = screw_char * count
        f.write(screw)
        f.close()
        return copy

    @staticmethod
    def _make_tmp_copy(path, suffix=None):
        """ Makes a copy of obj into CLE's tmp directory """
        if not os.path.exists('/tmp/cle'):
            os.mkdir('/tmp/cle')
        if os.path.exists(path):
            bn = os.urandom(5).encode('hex')
            if suffix is not None:
                bn += suffix
            dest = os.path.join('/tmp/cle', bn)
            l.info("\t -> copy obj %s to %s", path, dest)
            shutil.copy(path, dest)
        else:
            raise CLException("File %s does not exist :(. Please check that the"
                              " path is correct" % path)
        return dest

    def _check_arch(self, objpath):
        """ Is obj the same architecture as our main binary ? """
        arch = ArchInfo(objpath)
        # The architectures are exactly the same
        return self.main_bin.archinfo.compatible_with(arch)

    def _check_lib(self, sopath):
        try:
            if os.path.isfile(sopath):
                l.debug("\t--> Trying %s", sopath)
                if not self._check_arch(sopath):
                    l.debug("\t\t -> has wrong architecture")
                else:
                    l.debug("-->Found %s", sopath)
                    return True
        except UnknownFormatException:
            l.info("Binary with unknown format ignored: %s", sopath)
        return False

    def _all_so_exports(self):
        exports = {}
        for i in self.shared_objects:
            if len(i.exports) == 0:
                l.debug("Warning: %s has no exports", os.path.basename(i.path))

            for symb, addr in i.exports.iteritems():
                exports[symb] = addr
                #l.debug("%s has export %s@%x" % (i.binary, symb, addr))
        return exports

    def _so_name_from_symbol(self, symb):
        """ Which shared object exports the symbol @symb ?
            Returns the first match
        """
        for i in self.shared_objects:
            if symb in i.exports:
                return os.path.basename(i.path)

    def _resolve_imports_ida(self, b):
        """ Resolve imports using IDA.
            @b is the main binary
        """
        so_exports = self._all_so_exports()

        imports = b.imports
        for name, ea in imports.iteritems():
            # In the same binary
            if name in b.exports:
                newaddr = b.exports[name]
                #b.resolve_import_dirty(name, b.exports[name])
            # In shared objects
            elif name in so_exports:
                newaddr = so_exports[name]

            else:
                l.warning("[U] %s -> unable to resolve import (IDA) :(", name)
                continue

            l.info("[R] %s -> at 0x%08x (IDA)", name, newaddr)
            b.update_addrs([ea], newaddr)
