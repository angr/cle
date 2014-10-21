#!/usr/bin/env python

#from ctypes import *
import os
import logging
import collections
import shutil
import subprocess

from .elf import Elf
from .idabin import IdaBin
from .blob import Blob
from .archinfo import ArchInfo
from .clexception import CLException
import sys

#import platform
#import binascii

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
    the process.
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

        self.cle_ops = cle_ops # Load options passed to Cle
        self.memory = {} # Dictionary representation of the memory
        self.shared_objects =[] # Contains autodetected libraries (CLE binaries)
        self.dependencies = {} # {libname : vaddr} dict
        self._custom_dependencies = {} # {libname : vaddr} dict
        self._custom_shared_objects = [] # Contains manually specified libs (CLE binaries)
        self.ida_rebase_granularity = 0x1000000 # IDA workaround/fallback
        self.ida_main = False  # Is the main binary backed with ida ?
        self.path = None  # Path to the main binary
        self.skip_libs = [] # Libraries we don't want to load
        self.main_bin = None  # The main binary (i.e., the executable)
        self.auto_load_libs = False  # Shall we load the libraries the main binary depends on ?
        self.tmp_dir = None  # A temporary directory where we store copies of the binaries
        self.original_path = None  # The path to the original binary (before copy)
        self.except_on_ld_fail = False # Raise an exception when LD_AUDIT fails
        self.ignore_missing_libs = False # Raise an exception when a lib cannot be loaded
        self.custom_ld_path = None # Extra location to look for libraries
        self.ignore_imports = []  # Imports we don't want to resolve


        main_binary = str(main_binary)

        if len(cle_ops) == 0:
            l.info("No load_options passed to Cle")
        else:
            #import pdb; pdb.set_trace()
            # If just a dict is passed, we assume these options are for the main
            # binary, and we transform it into a dict of dict
            if type(cle_ops.values()[0]) != dict:
                nd = {}
                nd[main_binary] = cle_ops
                cle_ops = nd

        main_ops = {'backend':'elf'}
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
        self.__load_exe(main_binary, main_ops)
        for i in range(0, len(libs)):
                self.__make_custom_lib(libs[i], libs_ops[i])

        """
        From here, we have a coupe of options:

            1. The sole specified binary in an elf file: we autodetect
            dependencies, and load them.

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
            self.__manual_load(o)

        # Cases 2 and 5, skip dependencies resolution if the main binary is a blob
        if isinstance(self.main_bin, Blob):
            return

        # If we reach this point, the main binary is Elf.

        if self.main_bin.linking == 'static':
            "This binary was linked statically, there is nothing to resolve here"
            return;

        # We need to resolve dependencies here, even when auto_load_libs=False
        # because the SimProcedure resolution needs this info.

        self.dependencies = self.__ld_so_addr()

        if self.dependencies is None:
            l.warning("Could not get dependencies from LD, falling back to"
                      " static mode")
            self.dependencies = self.__ld_so_addr_fallback()

        if self.auto_load_libs is True:
            l.info("TODO: check for memory overlapping with manually loaded stuff")
            self.__auto_load_shared_libs()

        # Relocating stuff, resolving exports, etc. is done here
        self.__perform_reloc()

        # IDA backed stuff is not kept in sync with cle's mem, and the
        # relocations most likely altered it
        if (self.ida_main is True):
            self.ida_sync_mem()

    def host_endianness(self):
        if (sys.byteorder == "little"):
            return "LSB"
        else:
            return "MSB"

    def __perform_reloc(self):
        # Main binary
        self.__perform_reloc_stub(self.main_bin)

        l.info("TODO: relocations in custom loaded shared objects")
        # Libraries
        for obj in self.shared_objects:
            self.__perform_reloc_stub(obj)

            # Again, MIPS is a pain...
            if "mips" in obj.arch and isinstance(obj, Elf):
                obj.relocate_mips_jmprel()

    def __perform_reloc_stub(self, binary):
        """ This performs dynamic linking of all objects, i.e., calculate
            addresses of relocated symbols and resolve imports for each object.
            When using CLE without IDA, the rebasing and relocations are done by
            CLE based on information from Elf files.
            When using CLE with IDA, the rebasing is done with IDA, and
            relocations of symbols are done by CLE using the IDA API.
        """
        if isinstance(binary, IdaBin):
            self.__resolve_imports_ida(binary)
            # Once everything is relocated, we can copy IDA's memory to Ld
        else:
            self.__reloc(binary)

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
            self.__copy_mem(o, update=True)

    def mem_range(self, a_from, a_to):
        arr = []
        for addr in range(a_from, a_to):
            arr.append(self.memory[addr])
        return "".join(arr)

    def addr_belongs_to_object(self, addr):
        max = self.main_bin.get_max_addr()
        min = self.main_bin.get_min_addr()

        if (addr >= min and addr <= max):
            return self.main_bin

        for so in self.shared_objects:
            max = so.get_max_addr()
            min = so.rebase_addr
            if min == 0:
                raise CLException("Rebase address of object %s is 0, should be "
                                  "updated", os.path.basename(so.binary))
            if (addr >= min and addr <= max):
                return so

    def is_ida_mapped(self, addr):
        """
            Is the object mapping @addr an instance of IdaBin ?
        """
        return isinstance(IdaBin, self.addr_belongs_to_object(addr))

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
        """ The maximum address loaded as part of any loaded object """

        m1 = self.main_bin.get_max_addr()

        for i in self.shared_objects:
            m1 = max(m1, i.get_max_addr())

        for i in self._custom_shared_objects:
            m1 = max(m1, i.get_max_addr())

        return m1

    def __reloc(self, obj):
        """ Perform relocations of external references """

        l.debug("[Performing relocations of %s]" % obj.binary)

        # MIPS local GOT entries need relocation too (except for the main
        # binary as we don't relocate it).
        if "mips" in self.main_bin.arch and obj != self.main_bin:
            self.__reloc_mips_local(obj)

        # Now let's update GOT entries for PLT jumps
        for symb, got_addr in obj.jmprel.iteritems():
            # We don't resolve ignored functions
            if symb in self.ignore_imports:
                continue
            uaddr = self.find_symbol_addr(symb)
            if (uaddr):
                # We resolved this symbol
                obj.resolved_imports.append(symb)
                uaddr = uaddr + obj.rebase_addr
                l.info("\t--> [R] Relocation of %s -> 0x%x [stub@0x%x]" % (symb,
                                                                     uaddr,
                                                                     got_addr))

                baddr = self.__addr_to_bytes(uaddr)
                for i in range(0, len(baddr)):
                    self.memory[got_addr + i] = baddr[i]

            else:
                l.warning("\t--> [U] Cannot locate symbol \"%s\" from SOs" % symb)

    def __reloc_mips_local(self, obj):
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

        got_entry_size = obj.bits_per_addr / 8 # How many bytes per slot ?

        # Local entries reside in the first part of the GOT
        for i in range(0, obj.mips_local_gotno): # 0 to number of local symb
            got_slot = obj.gotaddr + obj.rebase_addr + (i * got_entry_size)
            addr = self.__bytes_to_addr(self.__read_got_slot(got_slot))
            if (addr == 0):
                l.error("Address in GOT at 0x%x is 0" % got_slot)
            else:
                newaddr = addr + delta
                l.debug("\t-->Relocating MIPS local GOT entry @ slot 0x%x from 0x%x"
                        " to 0x%x" % (got_slot, addr, newaddr))
                self.__override_got_slot(got_slot, newaddr)

    def __addr_to_bytes(self, addr):
        """ This splits an address into n bytes
        @addr is the address to split
        """

        # Craft format string of the right length
        hex_digits = self.main_bin.bits_per_addr / 4
        fmt = "0%dX" % hex_digits
        fmt = '%' + fmt

        # Convert addr to hex string
        hx = fmt % addr
        h_bytes = []

        # Split hex addr in bytes
        for i in range(0, len(hx), 2):
            val = int(hx[0:2],16)
            h = chr(val)
            h_bytes.append(h)
            hx = hx[2:]

        if self.main_bin.endianness == "LSB":
            h_bytes.reverse()

        return h_bytes

    def __bytes_to_addr(self, addr):
        """ Expects an array of bytes and returns an int"""
        sz = self.main_bin.bits_per_addr / 8

        if len(addr) != sz:  # Is it a proper address ?
            raise CLException("Address of size %d, was expecting %d" %
                              (len(addr), sz))

        # We are starting the conversion from the least significant byte
        if self.main_bin.endianness == "LSB":
            addr.reverse()

        res = 0
        shift = 0
        for i in addr:
            x = ord(i) << shift
            res = res + x
            shift = shift + 8 # We shit by a byte everytime...
        return res

    def __read_got_slot(self, got_slot):
        """ Reads the content of a GOT slot @ address got_slot """
        n_bytes = self.main_bin.bits_per_addr / 8
        s = []
        for i in range(0, n_bytes):
            s.append(self.memory[got_slot + i])
        return s

    def __override_got_slot(self, got_slot, newaddr):
        """ This overrides the got slot starting at address @got_slot with
        address @newaddr """
        split_addr = self.__addr_to_bytes(newaddr)

        for i in range(0, len(split_addr)):
            self.memory[got_slot + i] = split_addr[i]

    def override_got_entry(self, symbol, newaddr, obj):
        """ This overrides the address of the function defined by @symbol with
        the new address @newaddr, inside the GOT of object @obj.
        This is used to call simprocedures instead of actual code """

        got = obj.jmprel

        if not (symbol in got.keys()):
            l.debug("Could not override the address of symbol %s: symbol not "
                    "found" % symbol)
            return False

        self.__override_got_slot(got[symbol], newaddr)

        return True

    def find_symbol_addr(self, symbol):
        """ Try to get a symbol's address from the exports of shared objects """
        for so in self.shared_objects:
            ex = so.get_exports()
            if symbol in ex:
                return ex[symbol] + so.rebase_addr

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

    def __load_exe(self, path, main_binary_ops):
        """ Instanciate and load exe into "main memory
        """
        # Warning: when using IDA, the relocations will be performed in its own
        # memory, which we'll have to sync later with Ld's memory
        self.path = path
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

        # IDA specific crap
        if main_binary_ops['backend'] == 'ida':
            self.ida_main = True
            # If we use IDA, it needs a directory where it has permissions
            self.original_path = self.path
            path = self.__copy_obj(self.path)
            self.path = path

        # The backend defaults to Elf
        self.main_bin = self.__instanciate_binary(path, main_binary_ops)

        # Copy mem from object's private memory to Ld's address space
        self.__copy_mem(self.main_bin)

    def __make_custom_lib(self, path, ops):
        """
        Instanciate custom library (i.e., manyally specified lib) as opposed to auto-loading)
        Returns: nothing, it only appends the new binary to the custom shared objects dict
        """

        obj = self.__instanciate_binary(path, ops)
        self._custom_shared_objects.append(obj)

        # What library is that ? If nothing was specified, we use the filename
        if obj.provides is not None:
            dep = obj.provides
        else:
            dep = os.path.basename(path)

        self._custom_dependencies[dep] = obj.custom_base_addr if obj.custom_base_addr else 0

    def __manual_load(self, obj):
        """
        Manual loading stub.
        """
        # If no base address was specified, let's find one
        if obj.custom_base_addr is None:
            base = self.__get_safe_rebase_addr()
            obj.rebase_addr = base
        else:
            obj.rebase_addr = obj.custom_rebase_addr
        self.__copy_mem(obj, obj.rebase_addr)


    def __instanciate_binary(self, path, ops):
        """
        Simple stub function to instanciate the right type given the backend name
        """
        backend = ops['backend']

        if backend  == 'elf':
            obj = Elf(path)

        elif backend == 'ida':
            obj = IdaBin(path)

        elif backend == 'blob':
            obj = Blob(path)

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

    def __copy_mem(self, obj, rebase_addr = None, update = False):
        """ Copies private memory of obj to Ld's memory (the one we work with)
            if @rebase_addr is specified, all memory addresses of obj will be
            translated by @rebase_addr in memory.
            By default, Ld assumes nothing was previously loaded there and will
            raise an exception if it has to overwrite something, unless @update
            is set to True
        """
        for addr, val in obj.memory.iteritems():
            if (rebase_addr is not None):
                addr = addr + rebase_addr
            if addr in self.memory and not update:
                raise CLException("Something is already loaded at 0x%x" % addr)
            else:
                self.memory[addr] = val

    def __auto_load_shared_libs(self):
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

            fname = os.path.basename(name)
            # If we haven't determined any base address yet (probably because
            # LD_AUDIT failed)
            if addr == 0:
                addr = self.__get_safe_rebase_addr()

            if self.ida_main == True:
                so = self.__auto_load_so_ida(name)
            else:
                so = self.__auto_load_so_cle(name)

            if so is None :
                if fname in self.skip_libs:
                    l.debug("Shared object %s not loaded (skip_libs)" % name)
                else:
                    l.warning("Could not load lib %s" % fname)
                    if self.ignore_missing_libs is False:
                        raise CLException("Could not find suitable %s (%s), please copy it in the  binary's directory or set skip_libs = [\"%s\"]" % (fname, self.main_bin.archinfo.name, fname))
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

        self.__copy_mem(so, base)

    def __get_safe_rebase_addr(self):
        """
        Get a "safe" rebase addr, i.e., that won't overlap with already loaded stuff.
        This is used as a fallback when we cannot use LD to tell use where to load
        a binary object. It is also a workaround to IDA crashes when we try to
        rebase binaries at too high addresses.
        """
        granularity = self.ida_rebase_granularity
        base = self.max_addr() + (granularity - self.max_addr() % granularity)
        return base

    def __same_dir_shared_objects(self):
        """
        Returns the list of *.so found in the same directory as the main binary
        """
        so = {}
        curdir = os.path.dirname(self.original_path)
        for f in os.listdir(curdir):
            if os.path.isfile(os.path.join(curdir, f)) and ".so" in f:
                so[f] = 0
        return so

    def __ld_so_addr(self):
        """ Use LD_AUDIT to find object dependencies and relocation addresses"""

        qemu = self.main_bin.archinfo.get_qemu_cmd()
        env_p = os.getenv("VIRTUAL_ENV", "/")
        bin_p = os.path.join(env_p, "local/lib", self.main_bin.archinfo.get_unique_name())

        # Our LD_AUDIT shared object
        ld_audit_obj = os.path.join(bin_p, "cle_ld_audit.so")

        #LD_LIBRARY_PATH
        ld_path = os.getenv("LD_LIBRARY_PATH")
        if ld_path ==None:
            ld_path = bin_p
        else:
            ld_path = ld_path + ":" + bin_p

        cross_libs = self.main_bin.archinfo.get_cross_library_path()
        ld_libs = self.main_bin.archinfo.get_cross_ld_path()
        ld_path = ld_path + ":" + ld_libs

        var = "LD_LIBRARY_PATH=%s,LD_AUDIT=%s,LD_BIND_NOW=yes" % (ld_path, ld_audit_obj)

        # Let's work on a copy of the binary
        binary = self._binary_screwup_copy(self.path)

        #LD_AUDIT's output
        log = "./ld_audit.out"

        cmd = [qemu, "-strace", "-L", cross_libs, "-E", var, binary]
        s = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        s.communicate()

        # Our LD_AUDIT library is supposed to generate a log file.
        # If not we're in trouble
        if (os.path.exists(log)):
            libs = {}
            f = open(log,'r')
            for i in f.readlines():
                lib = i.split(",")
                if lib[0] == "LIB":
                    libs[lib[1]] = int(lib[2].strip(), 16)
            f.close()
            l.debug("---")
            for o,a in libs.iteritems():
                l.debug(" -> Dependency: %s @ 0x%x)" % (o,a) )

            l.debug("---")
            os.remove(log)
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
        copy = self.__copy_obj(path, suffix="screwed")
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

    def __ld_so_addr_fallback(self):
        """
        Sometimes, __ld_so_addr fails, because it relies on LD_AUDIT, and that
        won't work for binaries that have been compiled for a different ABI.
        In this case, we only extract the DT_NEEDED field of Elf binaries, and
        set 0 as the load address for SOs.
        """

        # This is hackish, but I haven't found a way to get extract DT_NEEDED
        # entries from the dynamic table using IDA
        if self.ida_main == True:
            elf_b = Elf(self.path, load=False)  # Use Elf to determine needed libs
            deps = elf_b.deps
        else:
            deps = self.main_bin.deps
        if deps is None:
            raise CLException("Could not find any dependencies for this binary,"
                              " this is most likely a bug")
        load = {}
        for i in deps:
            load[i] = 0
        return load

    def __auto_load_so_ida(self, soname, base_addr = None):
        """Ida cannot use system libraries because it needs write access to the
           same location to write its #@! db files.
        """

        # This looks for an existing /tmp/cle_blah/lib_blah.so
        dname = os.path.dirname(self.path)
        lib = os.path.basename(soname)
        sopath = os.path.join(dname,lib)

        # Otherwise, create cle's tmp dir and try to find the lib somewhere else
        if not os.path.exists(sopath) or not self.__check_arch(sopath):
            self.__make_tmp_dir()

            # Look in the same dir as the main binary
            orig_dname = os.path.dirname(self.original_path)
            so_orig = os.path.join(orig_dname, lib)

            if os.path.exists(so_orig) and self.__check_arch(so_orig):
                sopath = self.__copy_obj(so_orig)

            # finally let's find it somewhere in the system
            else:
                so_system = self.__search_so(soname)
                # If found, we make a copy of it in our tmpdir
                if so_system is not None:
                    sopath = self.__copy_obj(so_system)
                else:
                    return None

        obj = IdaBin(sopath, base_addr)
        return obj

    def __make_tmp_dir(self):
        """ Create CLE's tmp directory if it does not exists """
        if not os.path.exists(self.tmp_dir):
            os.mkdir(self.tmp_dir)


    def __copy_obj(self, path, suffix=None):
        """ Makes a copy of obj into CLE's tmp directory """
        self.__make_tmp_dir()
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

    def __auto_load_so_cle(self, soname):
        # Soname can be a path or just the name if the library, in which case we
        # search for it in known paths.

        if (os.path.exists(soname)):
            path = soname
        else:
            path = self.__search_so(soname)

        if path is not None:
            so = Elf(path)
            return so

    def __check_arch(self, objpath):
        """ Is obj the same architecture as our main binary ? """

        arch = ArchInfo(objpath)
        #The architectures are exactly the same
        return self.main_bin.archinfo.compatible_with(arch)

    def __search_so(self, soname):
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

        l.debug("Searching for SO %s" % libname)
        for ld_path in loc:
            #if not ld_path: continue
            for s_path, s_dir, s_file in os.walk(ld_path, followlinks=True):
                sopath = os.path.join(s_path,libname)
                if os.path.exists(sopath):
                    l.debug("\t--> Trying %s" % sopath)
                    if self.__check_arch(sopath) == False:
                        l.debug("\t\t -> has wrong architecture")
                    else:
                        l.debug("-->Found %s" % sopath)
                        return sopath

    def __all_so_exports(self):
        exports = {}
        for i in self.shared_objects:
            if len(i.exports) == 0:
                l.debug("Warning: %s has no exports" % os.path.basename(i.path))

            for symb, addr in i.exports.iteritems():
                exports[symb] = addr
                #l.debug("%s has export %s@%x" % (i.binary, symb, addr))
        return exports

    def __so_name_from_symbol(self, symb):
        """ Which shared object exports the symbol @symb ?
            Returns the first match
        """
        for i in self.shared_objects:
            if symb in i.exports:
                return os.path.basename(i.path)

    def __resolve_imports_ida(self, b):
        """ Resolve imports using IDA.
            @b is the main binary
        """
        so_exports = self.__all_so_exports()

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

    def read_bytes(self, addr, n):
        """ Read @n bytes at address @addr in memory and return an array of bytes
        """
        bytes = []
        for i in range(addr, addr+n):
            bytes.append(self.memory[i])
        return bytes

    # Test cases
    def test_end_conversion(self):
        x = self.__addr_to_bytes(int("0xc4f2", 16))
        y = self.__bytes_to_addr(x)

        print x
        print y

