#!/usr/bin/env python

# from ctypes import *
import os
import logging
import shutil
import subprocess

from .elf import Elf
from .idabin import IdaBin
from .blob import Blob
from .archinfo import ArchInfo
from .clexception import CLException, UnknownFormatException
from .memory import Clemory
import sys

# import platform
# import binascii

l = logging.getLogger("cle.ld")

"""
FIXME list
    1)  add support for per-library backend (right now, it all depends on the
        global flag ida_main, i.e., the main binary's backend.
    2)  Smart fallback: if no backend was specified and it the binary is NOT
        elf, fall back to blob
"""

class Ld(object):
    """ CLE ELF loader
    The loader loads all the objects and exports an abstraction of the memory of
    the process. What you see here is an address space with loaded and rebased
    binaries.  We try to use the same addresses as GNU Ld would use whenever we
    can, but it's not always possible.
    """

    def __init__(self, main_binary, cle_ops):
        """
        Cle expects:
            - @main_binary: the path to the main binary of the project
            - optionally, a dict as a set of parameters of the following form:
            {path1:{options1}, path2:{options2} etc.

            where:
                - each path is a distinct binary.
                - each set of options is a dict.

        Valid options are:

            @backend : 'ida' or 'elf' or 'blob' (defaults to 'elf')

        The following options are only relevant for the main binary:

            @auto_load_libs : bool ; shall we also load dynamic libraries ?
            @skip_libs = [] ; specific libs to skip, e.g., skip_libs=['libc.so.6']
            @except_on_ld_fail: bool ; shall we raise an exception if LD_AUDIT fails ?
            @ignore_missing_libs: bool ; shall we ignore missing libs (instead of exception)

        The following options override CLE's automatic detection:

            @custom_entry_point: the address of a custom entry point that will
                override CLE's automatic detection.
            @custom_base_addr: base address to load the binary
            @custom_offset: discard everything in the binary until this address

            @provides: which dependency is provided by the binary.
            This is used instead of what CLE would normally load for this
            dependency.
            e.g., provides = 'libc.so.6'.

        Example of valid parameters:
            {'/bin/ls': {backend:'elf', auto_load_libs:True, skip_libs:['libc.so.6']}}

        """

        # These are all the class variables of Ld
        # Please add new stuff here along with a description :)

        self.cle_ops = cle_ops  # Load options passed to Cle
        self.memory = Clemory()  # Dictionary representation of the memory
        self.shared_objects = []  # Contains autodetected libraries (CLE binaries)
        self.dependencies = {}  # {libname : vaddr} dict
        self._custom_dependencies = {}  # {libname : vaddr} dict
        self._custom_shared_objects = []  # Contains manually specified libs (CLE binaries)
        self.ida_rebase_granularity = 0x1000000  # IDA workaround/fallback
        self.ida_main = False  # Is the main binary backed with ida ?
        self.path = None  # Path to the main binary
        self.skip_libs = []  # Libraries we don't want to load
        self.main_bin = None  # The main binary (i.e., the executable)
        self.auto_load_libs = False  # Shall we load the libraries the main binary depends on ?
        self.tmp_dir = None  # A temporary directory where we store copies of the binaries
        self.original_path = None  # The path to the original binary (before copy)
        self.except_on_ld_fail = False  # Raise an exception when LD_AUDIT fails
        self.ignore_missing_libs = False  # Raise an exception when a lib cannot be loaded
        self.custom_ld_path = None  # Extra location to look for libraries
        self.ignore_imports = []  # Imports we don't want to resolve
        self.ignore_import_version_numbers = False  # if libx.so.0 also resolves libx.so
        self.ld_failed = None  # Whether using LD auditing interface failed
        self.ld_missing_libs = []  # missing libs that LD complains about

        main_binary = str(main_binary)

        if len(cle_ops) == 0:
            l.info("No load_options passed to Cle")
        else:
            #import pdb; pdb.set_trace()
            # If just a dict is passed, we assume these options are for the main
            # binary, and we transform it into a dict of dict
            if type(cle_ops.values()[0]) != dict:
                nd = {main_binary: cle_ops}
                cle_ops = nd

        main_ops = {'backend': 'elf'}
        libs = []
        libs_ops = []

        # Get the a list of binaries for which we have parameters
        for b, ops in cle_ops.iteritems():
            b = str(b)
            if 'backend' not in ops:
                ops['backend'] = 'elf'  # We default to Elf

            if b == main_binary:
                main_ops = ops
                continue

            else:
                libs.append(b)
                libs_ops.append(ops)

        # We load everything we got as specified in the parameters. This means
        # that custom shared libraries with custom options will be loaded
        # in place of autodetected stuff (which come later anyway)
        self._load_exe(main_binary, main_ops)
        for i in range(0, len(libs)):
            if not os.path.exists(libs[i]):
                path = self._search_so(os.path.basename(libs[i]))
            else:
                path = libs[i]
            self._make_custom_lib(path, libs_ops[i])

        """
        From here, we have a coupe of options:

            1. The sole specified binary in an elf file: we autodetect
            dependencies, and load them if auto_load_libs is True

            2. The sole binary is a blob: we load it and exit.

            3. All binaries are Elf files. We autodetect dependencies, and only
            load those that are not already provided by one of the specified
            binaries.  (See the provide option)

            4. The main binary is an Elf file, the rest is mixed:
                - We apply 3, and blobs replace autodetected dependencies if
                they provide the same library. Not sure how useful this is.

            5. The main binary is a blob. The rest is mixed:
                - We don't try to autodetect anything, we just load everything
                arbitrarily.
        """

        # Load custom binaries
        for o in self._custom_shared_objects:
            self._manual_load(o)

        # Cases 2 and 5, skip dependencies resolution if the main binary is a blob
        if isinstance(self.main_bin, Blob):
            return

        # If we reach this point, the main binary is Elf.

        if self.main_bin.linking == 'static':
            "This binary was linked statically, there is nothing to resolve here"
            return

        # We need to resolve dependencies here, even when auto_load_libs=False
        # because the SimProcedure resolution needs this info.

        self.dependencies = self._ld_so_addr()

        if self.dependencies is None:
            l.warning("Could not get dependencies from LD, falling back to"
                      " static mode")
            self.dependencies = self._ld_so_addr_fallback()

        if self.auto_load_libs is True:
            l.info("TODO: check for memory overlapping with manually loaded stuff")
            self._auto_load_shared_libs()

        # Relocating stuff, resolving exports, etc. is done here
        self._perform_reloc()

        # IDA backed stuff is not kept in sync with cle's mem, and the
        # relocations most likely altered it
        if (self.ida_main is True):
            self.ida_sync_mem()

    def _perform_reloc(self):

        l.info("TODO: relocations in custom loaded shared objects")
        # Libraries
        for obj in self.shared_objects:
            self._perform_reloc_stub(obj)

        # Main binary
        self._perform_reloc_stub(self.main_bin)
        # Again, MIPS is a pain...
        #   if "mips" in obj.arch and isinstance(obj, Elf):
        #       obj.relocate_mips_jmprel()

    def _perform_reloc_stub(self, binary):
        """ This performs dynamic linking of all objects, i.e., calculate
            addresses of relocated symbols and resolve imports for each object.
            When using CLE without IDA, the rebasing and relocations are done by
            CLE based on information from Elf files.
            When using CLE with IDA, the rebasing is done with IDA, and
            relocations of symbols are done by CLE using the IDA API.
        """
        if isinstance(binary, IdaBin):
            self._resolve_imports_ida(binary)
            # Once everything is relocated, we can copy IDA's memory to Ld
        else:
            self._reloc_got(binary)
            self._reloc_absolute(binary)
            self._reloc_relative(binary)
            self._reloc_global_copy(binary)

    def ida_sync_mem(self):
        """
            TODO: be smarter, and add a flag to IdaBin to toggle resync
        """
        objs = [self.main_bin]
        for i in self.shared_objects:
            if isinstance(i, IdaBin):
                objs.append(i)
            else:
                l.warning("Not syncing memory for %s, not IDA backed" % i.binary)

        for o in objs:
            l.info("**SLOW**: Copy IDA's memory to Ld's memory (%s)" % o.binary)
            self._copy_mem(o, update=True)

    def addr_belongs_to_object(self, addr):
        max = self.main_bin.get_max_addr()
        min = self.main_bin.get_min_addr()

        if (addr >= min and addr <= max):
            return self.main_bin

        for so in self.shared_objects:
            max = so.get_max_addr() + so.rebase_addr
            min = so.rebase_addr
            if min == 0:
                raise CLException(
                    "Rebase address of object %s is 0, it should have been updated already" % os.path.basename(
                        so.binary))
            if min <= addr <= max:
                return so
        return None

    def addr_is_ida_mapped(self, addr):
        """
            Is the object mapping @addr an instance of IdaBin ?
        """
        return isinstance(IdaBin, self.addr_belongs_to_object(addr))

    def addr_is_mapped(self, addr):
        """
        Is addr mapped at all ?
        """
        return self.addr_belongs_to_object(addr) is not None

    def min_addr(self):
        """ The minimum base address of any loaded object """

        # Let's start with the main executable
        if self.ida_main == True:
            return self.main_bin.get_min_addr()
        else:
            base = self.main_bin.get_min_addr()

        # Libraries usually have 0 as their base address, until relocation.
        # It is unlikely that libraries get relocated at a lower address than
        # the main binary, but we never know...
        for i in self.shared_objects:
            if (i.rebase_addr > 0 and i.rebase_addr < base):
                base = i.rebase_addr

        return base

    def max_addr(self):
        """
        The maximum address loaded as part of any loaded object (i.e., the whole address space)
        """

        m1 = self.main_bin.get_max_addr()

        for i in self.shared_objects:
            m1 = max(m1, i.get_max_addr() + i.rebase_addr)

        for i in self._custom_shared_objects:
            m1 = max(m1, i.get_max_addr() + i.rebase_addr)

        return m1


    def _reloc_global_copy(self, obj):
        """
        Type 5 on amd64 - copy the value of the resolved symbol instead of its
        address
        """
        for got_addr, symb in obj.copy_reloc:
            addr = self.find_symbol_addr(symb)
            if addr is None:
                raise CLException("Could not find address for symbol %s" % symb)
            val = self.memory.read_addr_at(addr, obj.archinfo)
            got_addr = got_addr + obj.rebase_addr
            self.memory.write_addr_at(got_addr, val, obj.archinfo)

    def _reloc_got(self, obj):
        """
        Perform relocations of jump slots (in practice, GOT entries)
        Type S
        """

        l.info("[Performing GOT relocations of %s]" % obj.binary)

        # MIPS local GOT entries need relocation too (except for the main
        # binary as we don't relocate it).
        if "mips" in self.main_bin.arch and obj != self.main_bin:
            self._reloc_mips_local(obj)

        """
        We need to update GOT entries of external symbols.
        These may be of type jmprel (jump type relocations,
        i.e., functions) or rela/rel for non functions.
        """

        # Now let's update GOT entries for both PLT jumps and global data
        ext = dict(obj.jmprel.items() + obj.global_reloc.items())
        for symb, got_addr in ext.iteritems():

            # We don't resolve ignored functions
            if symb in self.ignore_imports:
                continue

            if "mips" in self.main_bin.archinfo.name and obj != self.main_bin:
                delta = obj.rebase_addr - obj.mips_static_base_addr
                got_addr = got_addr + delta
            else:
                # We take the GOT from ELF file, that's not rebased yet
                got_addr = got_addr + obj.rebase_addr

            loc = "(external)"
            # Find_symbol_addr() already takes care of rebasing
            uaddr = self.find_symbol_addr(symb)

            if (uaddr):
                self.memory.write_addr_at(got_addr, uaddr, self.main_bin.archinfo)
                # We resolved this symbol
                obj.resolved_imports.append(symb)

                stype = "function" if symb in obj.jmprel else "global data ref"
                l.debug("\t--> [R] %s Relocation of %s %s -> 0x%x [stub@0x%x]" % (loc, stype, symb,
                                                                                  uaddr,
                                                                                  got_addr))

            else:
                l.warning("\t--> [U] Cannot locate symbol \"%s\" from SOs" % symb)

    def _reloc_absolute(self, obj):
        """
        Type S+A
        """

        l.info("[Performing absolute relocations of %s]" % obj.binary)
        for t in obj.s_a_reloc:
            name = t[0]
            off = t[1]
            off = off + obj.rebase_addr
            #if name in obj.resolved_imports:
            # Those relocations should be exported by the local module
            # BUT they can also be exported by other modules (e.g., PPC type 20)
            if obj.rela_type == "DT_RELA":
                addend = t[2]
            else:
                addend = self.memory.read_addr_at(off, self.main_bin.archinfo)

            if addend != 0:
                raise CLException("S+A reloc with an actual addend, what should we do with it ??")
            addr = self.find_symbol_addr(name)
            if addr is not None:
                self.memory.write_addr_at(off, addr, self.main_bin.archinfo)
                l.debug("\t-->[R] ABS relocation of %s -> 0x%x [at 0x%x]" % (name, addr, off))
            else:
                l.warning('[U] "%s" not relocated [instance at 0x%x]' % (name, off))

    def _reloc_relative(self, obj):
        """
        This is dealing with relative relocations, e.g., R_386_RELATIVE
        The relocation is B + A (base address + addend).
        """

        l.info("[Performing relative relocations of %s]" % obj.binary)
        # This is an array of tuples
        for t in obj.relative_reloc:
            offset = t[0]  # Offset in the binary where the address to relocate is stored

            vaddr = offset + obj.rebase_addr  # Where that is in memory as we loaded it

            if obj.rela_type == "DT_RELA":
                # DT_RELA specifies the addend explicitely
                addend = t[1]
            else:
                # DT_REL stores the addend in the memory location to be updated
                addend = self.memory.read_addr_at(vaddr, self.main_bin.archinfo)

            rela_updated = addend + obj.rebase_addr
            self.memory.write_addr_at(vaddr, rela_updated, self.main_bin.archinfo)
            l.debug("\t-->[R] Relative relocation, 0x%x [at 0x%x]" % (rela_updated, vaddr))

    def _reloc_mips_local(self, obj):
        """ MIPS local relocations (yes, GOT entries for local symbols also need
        relocation) """

        if obj.rebase_addr == 0:
            raise CLException("MIPS local GOT relocation only occurs to shared objects")

        delta = obj.rebase_addr - obj.mips_static_base_addr

        # If we load the shared library at the predefined base address, there's
        # nothing to do.
        if (delta == 0):
            l.debug("No need to relocate local symbols for this object")
            return

        elif (delta < 0):
            l.error("We are relocating a MIPS object at a lower address than"
                    " its static base address. This is weird.")

        got_entry_size = obj.bits_per_addr / 8  # How many bytes per slot ?

        # Local entries reside in the first part of the GOT
        for i in range(0, obj.mips_local_gotno):  # 0 to number of local symb
            got_slot = obj.pltgotaddr + obj.rebase_addr + (i * got_entry_size)
            addr = self.memory.read_addr_at(got_slot, self.main_bin.archinfo)
            if (addr == 0):
                l.error("Address in GOT at 0x%x is 0" % got_slot)
            else:
                newaddr = addr + delta
                l.debug("\t-->Relocating MIPS local GOT entry @ slot 0x%x from 0x%x"
                        " to 0x%x" % (got_slot, addr, newaddr))
                self.memory.write_addr_at(got_slot, newaddr, self.main_bin.archinfo)

    def get_relocated_mips_jmprel(self, obj):
        """ After we relocate an ELF object, we also need, in the case of MIPS,
        to relocate its GOT addresses relatively to its static base address.
        Note: according to the Elf specification, this ONLY applies to shared objects
        """

        l.warning("This function is deprecated and should not be used.")

        jmprel = {}
        # This should not be called for non rebased binaries (i.e., main
        # binaries)
        if obj.rebase_addr == 0:
            raise CLException("Attempting MIPS relocation with rebase_addr = 0")

        # Here, we shift all GOT addresses (the slots, not what they contain)
        # by a delta. This is because the MIPS compiler expected us to load the
        # binary at self.mips_static_base_addr)
        delta = obj.rebase_addr - obj.mips_static_base_addr
        l.info("Relocating MIPS GOT entries - static base addr is 0%x, acutal "
               "base addr is 0x%x" % (obj.mips_static_base_addr, obj.rebase_addr))
        for i, v in obj.get_mips_jmprel().iteritems():
            jmprel[i] = v + delta

        return jmprel

    def override_got_entry(self, symbol, newaddr, obj):
        """ This overrides the address of the function defined by @symbol with
        the new address @newaddr, inside the GOT of object @obj.
        This is used to call simprocedures instead of actual code """

        got = obj.jmprel

        if not (symbol in got.keys()):
            l.debug("Could not override the address of symbol %s: symbol entry not "
                    "found in GOT" % symbol)
            return False

        self.memory.write_addr_at(got[symbol], newaddr, self.main_bin.archinfo)
        return True

    """
    Search functions
    """

    def find_symbol_addr(self, symbol):
        """ Try to find the address of @symbol, if it is exported by any of the
        libraries or the main binary. We give priority to symbols with
        STB_GLOBAL binding, i.e., it takes precedence other any other symbol
        with binding STB_WEAK.
        """

        found = 0
        for so in set(self.shared_objects + [self.main_bin]):
            ex = so.exports
            if symbol in ex:
                for i in so.symbols:
                    if i["name"] == symbol:
                        binding = i["binding"]  # weak or global symbol ?
                        # We prefer STB_GLOBAL
                        if binding == "STB_GLOBAL" and ex[symbol] != 0:
                            return ex[symbol] + so.rebase_addr
                        elif binding == "STB_WEAK" and ex[symbol] != 0:
                            found = ex[symbol] + so.rebase_addr
        if found != 0:
            return found

        # If that doesn't do it, we also look into local symbols
        for so in set(self.shared_objects + [self.main_bin]):
            sb = so.symbol(symbol)
            if sb is not None:
                if sb['addr'] != 0:
                    return sb['addr']

    def find_symbol_name(self, addr):
        """ Return the name of the function starting at addr.
        """
        objs = [self.main_bin]
        objs = objs + self.shared_objects

        for o in objs:
            name = o.whatis(addr)
            if name is not None:
                return name

    def guess_function_name(self, addr):
        """
        Try to guess the name of the function at @addr
        WARNING: this is approximate
        """

        objs = [self.main_bin]
        objs = objs + self.shared_objects

        for o in objs:
            name = o.guess_function_name(addr)
            if name is not None:
                return name

    def find_module_name(self, addr):
        objs = [self.main_bin]
        objs = objs + self.shared_objects

        for o in objs:
            # The Elf class only works with static non-relocated addresses
            if o.contains_addr(addr - o.rebase_addr):
                return os.path.basename(o.binary)

    def find_symbol_got_entry(self, symbol):
        """ Look for the address of a GOT entry for symbol @symbol.
        If found, return the address, otherwise, return None
        """
        if type(self.main_bin) is IdaBin:
            if symbol in self.main_bin.imports:
                return self.main_bin.imports[symbol]
        elif type(self.main_bin) is Elf:
            if symbol in self.main_bin.jmprel:
                return self.main_bin.jmprel[symbol]

    def _load_exe(self, path, main_binary_ops):
        """ Instanciate and load exe into "main memory
        """
        # Warning: when using IDA, the relocations will be performed in its own
        # memory, which we'll have to sync later with Ld's memory
        self.path = path
        if main_binary_ops['backend'] == "blob":
            try:
                arch = main_binary_ops['archinfo']
            except:
                l.debug("No archinfo instance passed to Cle for blob")
                pass
        else:
            arch = ArchInfo(self.path).name
            self.tmp_dir = "/tmp/cle_" + os.path.basename(self.path) + "_" + arch

        if 'skip_libs' in main_binary_ops:
            self.skip_libs = main_binary_ops['skip_libs']

        if 'auto_load_libs' in main_binary_ops:
            self.auto_load_libs = main_binary_ops['auto_load_libs']

        if 'except_on_ld_fail' in main_binary_ops:
            self.except_on_ld_fail = main_binary_ops['except_on_ld_fail']

        if 'ignore_missing_libs' in main_binary_ops:
            self.ignore_missing_libs = main_binary_ops['ignore_missing_libs']

        if 'custom_ld_path' in main_binary_ops:
            self.custom_ld_path = main_binary_ops['custom_ld_path']

        if 'ignore_imports' in main_binary_ops:
            self.ignore_imports = main_binary_ops['ignore_imports']

        if 'ignore_import_version_numbers' in main_binary_ops:
            self.ignore_import_version_numbers = main_binary_ops['ignore_import_version_numbers']

        # IDA specific crap
        if main_binary_ops['backend'] == 'ida':
            self.ida_main = True
            # If we use IDA, it needs a directory where it has permissions
            self.original_path = self.path
            path = self._copy_obj(self.path)
            self.path = path

        # The backend defaults to Elf
        self.main_bin = self._instanciate_binary(path, main_binary_ops)

        # Copy mem from object's private memory to Ld's address space
        self._copy_mem(self.main_bin)

    def _make_custom_lib(self, path, ops):
        """
        Instanciate custom library (i.e., manyally specified lib) as opposed to auto-loading)
        Returns: nothing, it only appends the new binary to the custom shared objects dict
        """

        obj = self._instanciate_binary(path, ops)
        self._custom_shared_objects.append(obj)

        # What library is that ? If nothing was specified, we use the filename
        if obj.provides is not None:
            dep = obj.provides
        else:
            dep = os.path.basename(path)

        self._custom_dependencies[dep] = obj.custom_base_addr if obj.custom_base_addr else 0

    def _manual_load(self, obj):
        """
        Manual loading stub.
        """
        # If no base address was specified, let's find one
        if obj.custom_base_addr is None:
            base = self._get_safe_rebase_addr()
            obj.rebase_addr = base
        else:
            obj.rebase_addr = obj.custom_rebase_addr
        self._copy_mem(obj, obj.rebase_addr)


    def _instanciate_binary(self, path, ops):
        """
        Simple stub function to instanciate the right type given the backend name
        """
        backend = ops['backend']

        if backend == 'elf':
            obj = Elf(path)

        elif backend == 'ida':
            obj = IdaBin(path)

        elif backend == 'blob':
            if 'custom_base_addr' not in ops.keys() \
                    or 'custom_entry_point' not in ops.keys() \
                    or 'custom_arch' not in ops.keys():
                raise CLException("Blob needs a custom_entry_point, custom_"
                                  "base_addr and custom_arch passed as cle options")

            obj = Blob(path, custom_entry_point=ops['custom_entry_point'],
                       custom_base_addr=ops['custom_base_addr'],
                       custom_offset=ops['custom_offset'], custom_arch=ops['custom_arch'])

        else:
            raise CLException("Unknown backend %s" % backend)

        if 'custom_base_addr' in ops:
            obj.custom_base_addr = ops['custom_base_addr']

        if 'custom_entry_point' in ops:
            obj.custom_entry_point = ops['custom_entry_point']

        if 'custom_offset' in ops:
            obj.custom_offset = ops['custom_offset']

        if 'provides' in ops:
            obj.provides = ops['provides']

        return obj

    def _copy_mem(self, obj, rebase_addr=None, update=False):
        """ Copies private memory of obj to Ld's memory (the one we work with)
            if @rebase_addr is specified, all memory addresses of obj will be
            translated by @rebase_addr in memory.
            By default, Ld assumes nothing was previously loaded there and will
            raise an exception if it has to overwrite something, unless @update
            is set to True
        """
        for addr, val in obj._memory.iteritems():
            if (rebase_addr is not None):
                addr = addr + rebase_addr
            if addr in self.memory and not update:
                raise CLException("Something is already loaded at 0x%x" % addr)
            else:
                self.memory[addr] = val

    def _auto_load_shared_libs(self):
        """ Load and rebase shared objects """
        # shared_libs = self.main_bin.deps
        shared_libs = self.dependencies
        for name, addr in shared_libs.iteritems():

            # If a custom loaded object already provides the same dependency as
            # what we autodetected, let's skip that
            if name in self._custom_dependencies:
                continue

            if name in self.skip_libs:
                continue

            if len(name) == 0:
                l.warning(
                    "***Library with no name at 0x%x. You are probably trying to load a shared object as the main library. If that's the case, its base address will be 0 instead of 0x%x. If that's not the case, this is probably a bug.***" % (
                        addr, addr))
                continue

            fname = os.path.basename(name)
            # If we haven't determined any base address yet (probably because
            # LD_AUDIT failed)
            if addr == 0:
                addr = self._get_safe_rebase_addr()

            if self.ida_main == True:
                so = self._auto_load_so_ida(name)
            else:
                so = self._auto_load_so_cle(name)

            if so is None:
                if fname in self.skip_libs:
                    l.debug("Shared object %s not loaded (skip_libs)" % name)
                else:
                    l.warning("Could not load lib %s" % fname)
                    if self.ignore_missing_libs is False:
                        raise CLException(
                            "Could not find suitable %s (%s), please copy it in the  binary's directory or set skip_libs = [\"%s\"]" % (
                                fname, self.main_bin.archinfo.name, fname))
            else:
                self.rebase_lib(so, addr)
                so.rebase_addr = addr
                self.shared_objects.append(so)

    def rebase_lib(self, so, base):
        """ Relocate a shared objet given a base address
        We actually copy the local memory of the object at the new computed
        address in the "main memory" """

        if isinstance(so, IdaBin):
            so.rebase(base)
            return

        if "mips" in so.arch and isinstance(so, Elf):
            l.debug("\t--> rebasing %s @0x%x (instead of static base addr 0x%x)" %
                    (so.binary, base, so.mips_static_base_addr))
        else:
            l.info("[Rebasing %s @0x%x]" % (os.path.basename(so.binary), base))

        self._copy_mem(so, base)

    def _get_safe_rebase_addr(self):
        """
        Get a "safe" rebase addr, i.e., that won't overlap with already loaded stuff.
        This is used as a fallback when we cannot use LD to tell use where to load
        a binary object. It is also a workaround to IDA crashes when we try to
        rebase binaries at too high addresses.
        """
        granularity = self.ida_rebase_granularity
        base = self.max_addr() + (granularity - self.max_addr() % granularity)
        return base

    def _same_dir_shared_objects(self):
        """
        Returns the list of *.so found in the same directory as the main binary
        """
        so = {}
        curdir = os.path.dirname(self.original_path)
        for f in os.listdir(curdir):
            if os.path.isfile(os.path.join(curdir, f)) and ".so" in f:
                so[f] = 0
        return so

    def _get_static_deps(self, obj):
        """
        Static deps because we statically read it from the Elf file (as opposed to ask GNU ld)
        """
        if type(obj) is Elf:
            return obj.deps
        elif type(obj) is IdaBin:
            elf_b = Elf(self.path, load=False)  # Use Elf to determine needed libs
            return elf_b.deps
        elif type(obj) is Blob:
            return []
        else:
            raise CLException("I don't know how to get deps for this type of binary")

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
        if self.custom_ld_path is not None:
            ld_path = self.custom_ld_path + ":" + ld_path

        var = "LD_LIBRARY_PATH=%s,LD_AUDIT=%s,LD_BIND_NOW=yes" % (ld_path, ld_audit_obj)

        # Let's work on a copy of the binary
        binary = self._binary_screwup_copy(self.path)

        #LD_AUDIT's output
        log = "./ld_audit.out"

        cmd = [qemu, "-strace", "-L", cross_libs, "-E", var, binary]
        s = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # Check stderr for library loading issues
        err = s.stderr.readlines()
        msg = "cannot open shared object file"

        deps = self._get_static_deps(self.main_bin)

        for dep in deps:
            for str_e in err:
                if dep in str_e and msg in str_e:
                    l.error("LD could not find dependency %s." % dep)
                    l.error("GNU LD will stop looking for libraries to load if "
                            "it doesn't find one of them.")
                    self.ld_missing_libs.append(dep)
                    break

        s.communicate()

        # Our LD_AUDIT library is supposed to generate a log file.
        # If not we're in trouble
        if (os.path.exists(log)):
            libs = {}
            f = open(log, 'r')
            for i in f.readlines():
                lib = i.split(",")
                if lib[0] == "LIB":
                    libs[lib[1]] = int(lib[2].strip(), 16)
            f.close()
            l.debug("---")
            for o, a in libs.iteritems():
                l.debug(" -> Dependency: %s @ 0x%x)" % (o, a))

            l.debug("---")
            os.remove(log)
            self.ld_failed = False
            return libs

        else:

            l.error("Could not find library dependencies using ld."
                    " The log file '%s' does not exist, did qemu fail ? Try to run "
                    "`%s` manually to check" % (log, " ".join(cmd)))
            l.info("Will fallback to alternate loading mode. The addresses won't "
                   "match qemu's addresses anymore, and only libraries from the "
                   "current directory will be loaded.")

            if self.except_on_ld_fail:
                raise CLException("Could not find library dependencies using ld.")
            else:
                self.ld_failed = True

            return None

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
        copy = self._copy_obj(path, suffix="screwed")
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

    def _ld_so_addr_fallback(self):
        """
        Sometimes, _ld_so_addr fails, because it relies on LD_AUDIT, and that
        won't work for binaries that have been compiled for a different ABI.
        In this case, we only extract the DT_NEEDED field of Elf binaries, and
        set 0 as the load address for SOs.
        """

        deps = self._get_static_deps(self.main_bin)
        if deps is None:
            raise CLException("Could not find any dependencies for this binary,"
                              " this is most likely a bug")
        load = {}
        for i in deps:
            load[i] = 0
        return load

    def _auto_load_so_ida(self, soname, base_addr=None):
        """Ida cannot use system libraries because it needs write access to the
           same location to write its #@! db files.
        """

        # This looks for an existing /tmp/cle_blah/lib_blah.so
        dname = os.path.dirname(self.path)
        lib = os.path.basename(soname)
        sopath = os.path.join(dname, lib)

        # Otherwise, create cle's tmp dir and try to find the lib somewhere else
        if not os.path.exists(sopath) or not self._check_arch(sopath):
            self._make_tmp_dir()

            # Look in the same dir as the main binary
            orig_dname = os.path.dirname(self.original_path)
            so_orig = os.path.join(orig_dname, lib)

            if os.path.exists(so_orig) and self._check_arch(so_orig):
                sopath = self._copy_obj(so_orig)

            # finally let's find it somewhere in the system
            else:
                so_system = self._search_so(soname)
                # If found, we make a copy of it in our tmpdir
                if so_system is not None:
                    sopath = self._copy_obj(so_system)
                else:
                    return None

        obj = IdaBin(sopath, base_addr)
        return obj

    def _make_tmp_dir(self):
        """ Create CLE's tmp directory if it does not exists """
        if not os.path.exists(self.tmp_dir):
            os.mkdir(self.tmp_dir)


    def _copy_obj(self, path, suffix=None):
        """ Makes a copy of obj into CLE's tmp directory """
        self._make_tmp_dir()
        if os.path.exists(path):
            if suffix is None:
                bn = os.path.basename(path)
            else:
                bn = os.path.basename(path) + "_" + suffix
            dest = os.path.join(self.tmp_dir, bn)
            l.info("\t -> copy obj %s to %s" % (path, dest))
            shutil.copy(path, dest)
        else:
            raise CLException("File %s does not exist :(. Please check that the"
                              " path is correct" % path)
        return dest

    def _auto_load_so_cle(self, soname):
        # Soname can be a path or just the name if the library, in which case we
        # search for it in known paths.

        if (os.path.exists(soname)):
            path = soname
        else:
            path = self._search_so(soname)

        if path is not None:
            so = Elf(path)
            return so

    def _check_arch(self, objpath):
        """ Is obj the same architecture as our main binary ? """

        arch = ArchInfo(objpath)
        # The architectures are exactly the same
        return self.main_bin.archinfo.compatible_with(arch)

    def _check_lib(self, sopath):
        try:
            if os.path.isfile(sopath):
                l.debug("\t--> Trying %s" % sopath)
                if not self._check_arch(sopath):
                    l.debug("\t\t -> has wrong architecture")
                else:
                    l.debug("-->Found %s" % sopath)
                    return True
        except UnknownFormatException, ex:
            l.info("Binary with unknown format ignored: %s", sopath)
        return False

    def _search_so(self, soname):
        """ Looks for a shared object given its filename"""

        # Normally we should not need this as LD knows everything already. But
        # in case we need to look for stuff manually...
        loc = []
        loc.append(os.path.dirname(self.path))
        if self.custom_ld_path is not None:
            loc.append(self.custom_ld_path)
        arch_lib = self.main_bin.archinfo._arch_paths()
        loc = loc + arch_lib
        # Dangerous, only ok if the hosts sytem's is the same as the target
        #loc.append(os.getenv("LD_LIBRARY_PATH"))

        libname = os.path.basename(soname)

        l.debug("Searching for SO %s in %s", libname, str(loc))
        for ld_path in loc:
            #if not ld_path: continue
            for s_path, s_dir, files in os.walk(ld_path, followlinks=True):
                sopath = os.path.join(s_path, libname)
                if libname in files and self._check_lib(sopath):
                    return sopath
                elif self.ignore_import_version_numbers:
                    for file in files:
                        if file.startswith(libname):
                            sopath = os.path.join(s_path, file)
                            l.debug("-->Found with version number: %s" % libname)
                            if self._check_lib(sopath):
                                return sopath

    def _all_so_exports(self):
        exports = {}
        for i in self.shared_objects:
            if len(i.exports) == 0:
                l.debug("Warning: %s has no exports" % os.path.basename(i.path))

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
