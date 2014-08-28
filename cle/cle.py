#!/usr/bin/env python

#from ctypes import *
import os
import logging
import pdb
#import collections
import shutil
import subprocess

from .elf import Elf
from .idabin import IdaBin
from .archinfo import ArchInfo
from .clexception import CLException
import sys

#import platform
#import binascii

l = logging.getLogger("cle.ld")


class Ld(object):
    """ CLE ELF loader
    The loader loads all the objects and exports an abstraction of the memory of
    the process.
    """
    def __init__(self, binary, force_ida=None, load_libs=None, skip_libs=None):
        """ @path is the path to licle_ctypes.so"""

        # IDA needs a directory where it has permissions
        arch = ArchInfo(binary).name
        self.tmp_dir = "/tmp/cle_" + os.path.basename(binary) + "_" + arch

        self.memory = {} # Dictionary representation of the memory
        self.shared_objects =[] # Executables and libraries's binary objects
        self.dependencies = {}
        self.path = binary
        self.force_ida = force_ida
        self.ida_rebase_granularity = 0x1000000 # IDA workaround
        if skip_libs is None:
            self.skip_libs = []
        else:
            self.skip_libs = skip_libs


        if self.force_ida is None:
            self.force_ida = False

        if (force_ida == True):
            self.original_path = binary
            self.path = self.__copy_obj(binary)
            self.force_ida = True
            self.main_bin = IdaBin(self.path)
        else:
            self.main_bin = Elf(binary)

        self.__load_exe()

        self.dependencies = self.__ld_so_addr()

        if load_libs is False:
            return
        #print "mem@ 0x601000: %s" % repr(self.memory[0x601000])
        self.__load_shared_libs()
        #print "mem@ 0x601000: %s" % repr(self.memory[0x601000])
        self.__perform_reloc()
        #print "mem@ 0x601000: %s" % repr(self.memory[0x601000])

        if (self.force_ida == True):
            self.ida_sync_mem()

    def host_endianness(self):
        if (sys.byteorder == "little"):
            return "LSB"
        else:
            return "MSB"

    def __perform_reloc(self):
        # Main binary
        self.__perform_reloc_stub(self.main_bin)

        # Libraries
        for obj in self.shared_objects:
            self.__perform_reloc_stub(obj)
            # Again, MIPS is a pain...
            if "mips" in obj.arch and self.force_ida is None:
                obj.relocate_mips_jmprel()

    def __perform_reloc_stub(self, binary):
        """ This performs dynamic linking of all objects, i.e., calculate
            addresses of relocated symbols and resolve imports for each object.
            When using CLE without IDA, the rebasing and relocations are done by
            CLE based on information from Elf files.
            When using CLE with IDA, the rebasing is done with IDA, and
            relocations of symbols are done by CLE using the IDA API.
        """
        if (self.force_ida):
            self.__resolve_imports_ida(binary)
            # Once everything is relocated, we can copy IDA's memory to Ld
        else:
            self.__reloc(binary)

    def ida_sync_mem(self):
        objs = [self.main_bin]
        for i in self.shared_objects:
            objs.append(i)

        for o in objs:
            l.debug("%s: Copy IDA's memory to Ld's memory" % o.binary)
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

    def min_addr(self):
        """ The minimum base address of any loaded object """

        # Let's start with the main executable
        if self.force_ida == True:
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
            m2 = i.get_max_addr()
            if m2 > m1:
                m1 = m2
        return m1

    def __reloc(self, obj):
        """ Perform relocations of external references """

        l.debug(" [Performing relocations of %s]" % obj.binary)

        # As usual, MIPS is different...
        if "mips" in self.main_bin.arch:
            self.__reloc_mips_local(obj)

        # Now let's update GOT entries for PLT jumps
        for symb, got_addr in obj.jmprel.iteritems():
            uaddr = self.find_symbol_addr(symb)
            if (uaddr):
                uaddr = uaddr + obj.rebase_addr
                l.debug("\t--> [R] Relocation of %s -> 0x%x [stub@0x%x]" % (symb,
                                                                     uaddr,
                                                                     got_addr))

                baddr = self.__addr_to_bytes(uaddr)
                for i in range(0, len(baddr)):
                    self.memory[got_addr + i] = baddr[i]

            else:
                l.debug("\t--> [U] Cannot locate symbol \"%s\" from SOs" % symb)

    def __reloc_mips_local(self, obj):
        """ MIPS local relocations (yes, GOT entries for local symbols also need
        relocation) """

        # If we load the shared library at the predefined base address, there's
        # nothing to do.
        delta = obj.rebase_addr - obj.mips_static_base_addr
        if (delta == 0):
            l.debug("No need to relocate local symbols for this object")
            return

        got_entry_size = obj.bits_per_addr / 8 # How many bytes per slot ?

        # Local entries reside in the first part of the GOT
        for i in range(0, obj.mips_local_gotno): # 0 to number of local symb
            got_slot = obj.gotaddr + obj.rebase_addr + (i * got_entry_size)
            addr = self.__bytes_to_addr(self.__read_got_slot(got_slot))
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

    def __load_exe(self):
        """ Load exe into "main memory
        """
        # Warning: when using IDA, the relocations will be performed in its own
        # memory, which we'll have to sync later with Ld's memory
        self.__copy_mem(self.main_bin)

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

    def __load_shared_libs(self):
        """ Load and rebase shared objects """
        # shared_libs = self.main_bin.deps
        shared_libs = self.dependencies
        for name, addr in shared_libs.iteritems():

            fname = os.path.basename(name)
            # IDA
            if self.force_ida == True:
                addr = self.__ida_rebase_addr() # workaround for IDA crash
                so = self.__load_so_ida(name)
            else:
                so = self.__load_so_cle(name)

            if so is None :
                if fname not in self.skip_libs:
                    raise CLException("Could not find suitable %s (%s), please copy it in the "
                                      "binary's directory or set skip_libs = "
                                      "[\"%s\"]" % (fname, self.main_bin.archinfo.name, fname))
                else:
                    l.debug("Shared object %s not loaded (skip_libs)" % name)
            else:
                self.rebase_lib(so, addr)
                so.rebase_addr = addr
                self.shared_objects.append(so)

    def rebase_lib(self, so, base):
        """ Relocate a shared objet given a base address
        We actually copy the local memory of the object at the new computed
        address in the "main memory" """

        if self.force_ida == True:
            so.rebase(base)
            return # IDA already rebased stuff at load time

        else:
            if "mips" in so.arch:
                l.debug("\t--> rebasing %s @0x%x (instead of 0x%x)" %
                (so.binary, base, so.mips_static_base_addr))
            else:
                l.debug("[Rebasing %s @0x%x]" % (os.path.basename(so.binary), base))
            self.__copy_mem(so, base)

    def __ida_rebase_addr(self):
        """ IDA crashes if we try to rebase binaries at too high addresses..."""
        granularity = self.ida_rebase_granularity
        base = self.max_addr() + (granularity - self.max_addr() % granularity)
        return base

    def __ld_so_addr(self):
        """ Use LD_AUDIT to find object dependencies and relocation addresses"""

        qemu = self.main_bin.archinfo.get_qemu_cmd()
        env_p = os.getenv("VIRTUAL_ENV")
        bin_p = os.path.join(env_p, "local/lib" ,self.main_bin.arch)

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

        var = "LD_LIBRARY_PATH=%s,LD_AUDIT=%s" % (ld_path, ld_audit_obj)

        #LD_AUDIT's output
        log = "./ld_audit.out"

        cmd = [qemu, "-L", cross_libs, "-E", var, self.path]
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
            raise CLException("Could not find library dependencies using ld."
                " The log file '%s' does not exist, did qemu fail ? Try to run "
                              "`%s` manually to check" % (log, " ".join(cmd)))

    def __load_so_ida(self, soname, base_addr = None):
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


    def __copy_obj(self, path):
        """ Makes a copy of obj into CLE's tmp directory """
        self.__make_tmp_dir()
        if os.path.exists(path):
            dest = os.path.join(self.tmp_dir, os.path.basename(path))
            l.info("\t -> copy obj %s to %s" % (path, dest))
            shutil.copy(path, dest)
        else:
            raise CLException("File %s does not exist :(. Please check that the"
                              " path is correct" % path)
        return dest

    def __load_so_cle(self, soname):
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

        # Hack: there are plenty of arm variants
        # TODO: check Endianness
        if "arm" in arch.name and "arm" in self.main_bin.archinfo.name:
            return True

        return self.main_bin.archinfo.name == arch.name

    def __search_so(self, soname):
        """ Looks for a shared object given its filename"""

        # Normally we should not need this as LD knows everything already. But
        # in case we need to look for stuff manually...
        loc = []
        loc.append(os.path.dirname(self.path))
        arch_lib = self.main_bin.archinfo.get_cross_library_path()
        loc.append(arch_lib)
        # Dangerous, only ok if the hosts sytem's is the same as the target
        #loc.append(os.getenv("LD_LIBRARY_PATH"))

        libname = os.path.basename(soname)

        l.debug("Searching for SO %s" % libname)
        for ld_path in loc:
            #if not ld_path: continue
            for s_path, s_dir, s_file in os.walk(ld_path):
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

            l.debug("[R] %s -> at 0x%08x (IDA)", name, newaddr)
            b.update_addrs([ea], newaddr)

    # Test cases
    def test_end_conversion(self):
        x = self.__addr_to_bytes(int("0xc4f2", 16))
        y = self.__bytes_to_addr(x)

        print x
        print y

