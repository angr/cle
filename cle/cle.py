#!/usr/bin/env python

from ctypes import *
import os
import logging
import subprocess
import pdb
import collections

#import platform
#import binascii

l = logging.getLogger("cle")

class CLException(Exception):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return repr(self.val)


class Segment(object):
    """ Simple representation of an ELF file segment"""
    def __init__(self, name, vaddr, size, offset=None):
        self.vaddr = vaddr
        self.size = size
        self.offset = offset
        self.name = name

    def contains_addr(self, addr):
            return ((addr > self.vaddr) and (addr < self.vaddr + self.size))


class ArchInfo(object):
    """ This class extracts architecture information from ELF binaries using the
        cle_bfd library.
    """

    # There is a dozen of types of mips and arm CPUs reported from libbfd
    mips_names = ["mips:isa32", "mips:3000"]
    ppc_names = ["powerpc:common"]
    arm_names = ["arm", "armv4t"]

    def __init__(self, binary):
        """ Getarchitecture information from the binary file @binary using
        ctypes and cle_bfd.so """
        env_p = os.getenv("VIRTUAL_ENV")
        lib_p = "lib"
        lib = os.path.join(env_p, lib_p, "cle_bfd.so")
        if os.path.exists(lib):
            self.lib = cdll.LoadLibrary(lib)
            self.lib.get_bfd_arch_pname.restype = c_char_p

            self.name = self.lib.get_bfd_arch_pname(binary)
            self.bpa = self.lib.get_bits_per_addr(binary)
            self.asz = self.lib.get_arch_size(binary)

            self.qemu_arch = self.to_qemu_arch(self.name)
            self.simuvex_arch = self.to_simuvex_arch(self.name)
            self.ida_arch = self.to_ida_arch(self.name)
        else:
            raise CLException("Cannot load cle_bfd.so, invalid path:%s" % lib)


    def to_qemu_arch(self, arch):
        """ We internally use the BFD architecture names.
         This converts names to the convension used by qemu-user to name its
         different qemu-{arch} architectures. """

        if arch == "i386:x86-64":
            return "x86_64"
        elif arch in mips_names:
            return "mips"
        elif arch in ppc_names:
            return "ppc"
        elif arch in arm_names:
            return "arm"
        elif arch == "i386":
            return "i386"

        else:
            raise CLException("Architecture name conversion not implemented yet"
                              "for \"%s\" !" % arch)

    def to_simuvex_arch(self, arch):
        """ This function translates architecture names from the BFD convention
        to the convention used by simuvex """

        if arch == "i386:x86-64":
            return "AMD64"
        elif "mips" in arch and self.archinfo.arch_size == 32:
            return "MIPS32"
        elif arch in ppc_names:
            return "PPC32"
        elif arch in arm_names:
            return "ARM"
        elif arch == "i386":
            return "X86"
        # Unsupported architectures:
        elif "mips" in arch and self.archinfo.arch_size == 64:
            raise CLException("Architecture MIPS 64 bit not supported")
        elif "ppc" in arch and self.archinfo.arch_size == 64:
            raise CLException("Architecture PPC 64 bit not supported")
        # mipsel
        elif "mips" in arch and self.endianness == "LSB":
            l.info("Warning: arch mipsel detected, make sure you compile VEX "
                   "accordingly")
        else:
            raise CLException("Unknown architecture")

    def to_ida_arch(self, arch):
        if "i386" in arch:
            return "metapc"
        elif "arm" in arch:
            return "armb"
        elif "mips" in arch:
            return "mipsb"
        elif "powerpc" in arch:
            return "ppc"
        else:
            raise CLException("Unknown architecture")



class IdaBin(object):
    """ Get informations from binaries using IDA. This replaces the old Binary
    class and integrates it into CLE as a fallback """
    def __init__(self, binary, base_addr):
        archinfo = Archinfo(binary)
        processor_type = archinfo.ida_arch
        if(archinfo.bpa == 32):
            ida_prog = "idal"
        else:
            ida_prog = "idal64"

        pull = base_addr is None
        self.ida = idalink.IDALink(binary, ida_prog=ida_prog, pull=pull,
                                   processor_type=processor_type)


        self.imports = self.__get_imports()
        export_names = [e[0] for e in self.get_exports()]
        self.ida_symbols = self.__lookup_symbols(export_names)
        self.memory = self.ida.mem()
        self.entry_point = self.__get_entry_point()

    def rebase(base_addr):
        """ Rebase binary at address @base_addr """
        if base_addr is not None:
            if self.min_addr() >= base_addr:
                l.debug("It looks like the current idb is already rebased!")
            else:
                if self.ida.idaapi.rebase_program(
                    base_addr, self.ida.idaapi.MSF_FIXONCE |
                    self.ida.idaapi.MSF_LDKEEP) != 0:
                    raise Exception("Rebasing of %s failed!", self.filename)
            self.ida.remake_mem()


    def __lookup_symbols(self, symbols):
        """ Resolves a bunch of symbols denoted by the list @symbols
            Returns: a dict of the form {symb:addr}"""
        addrs = {}

        for sym in symbols:
            addr = self.__get_symbol_addr(sym)
            if not addr:
                l.debug("Symbol %s was not found (IDA)" % sym)
                continue
            addrs[sym] = addr

    def __get_symbol_addr(self, sym):
        """ Get the address of the symbol @sym from IDA
            Returns: an address
        """
        addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
        if addr == self.ida.idc.BADADDR:
            addr = None

    def __get_exports(self):
        """ Lookup exports names and resolves addresses.
            Returns: a dictonary of the form {export : addr}
        """
        export_names = [e[0] for e in self.__get_exports_names()]
        exports = self.__lookup_symbols(export_names)
        return exports

    def __get_exports_names(self):
        """ Get binary's exports names from IDA and return a list"""
        export_item_list = []
        for item in list(self.ida.idautils.Entries()):
            i = ExportEntry(item[0], item[1], item[2], item[3])
            export_item_list.append(i)
        return export_item_list

    def __get_imports(self):
        """ Extract imports from binary (IDA)"""
        import_modules_count = self.ida.idaapi.get_import_module_qty()

        for i in xrange(0, import_modules_count):
            self.current_module_name = self.ida.idaapi.get_import_module_name(
                i)
            self.ida.idaapi.enum_import_names(i, self.__import_entry_callback)

        return self.import_list

    def __import_entry_callback(self, ea, name, entry_ord):
        item = ImportEntry(self.current_module_name, ea, name, entry_ord)
        self.import_list.append(item)
        return True

    def min_addr(self):
        """ Get the min address of the binary (IDA)"""
        nm = self.ida.idc.NextAddr(0)
        pm = self.ida.idc.PrevAddr(nm)

        if pm == self.ida.idc.BADADDR:
            return nm
        else:
            return pm

    def max_addr(self):
        """ Get the max address of the binary (IDA)"""
        pm = self.ida.idc.PrevAddr(self.ida.idc.MAXADDR)
        nm = self.ida.idc.NextAddr(pm)

        if nm == self.ida.idc.BADADDR:
            return pm
        else:
            return nm

    def __get_entry_point(self):
        """ Get the entry point of the binary (from IDA)"""
        if self._custom_entry_point is not None:
            return self._custom_entry_point
        return self.ida.idc.BeginEA()



class Elf(object):
    """ Representation of loaded Elf binaries """
    def __init__(self, binary):

        self.segments = [] # List of segments
        self.memory = {} # Private virtual address space, without relocations
        self.symbols = None # Object's symbols
        self.rebase_addr = 0
        self.object_type = None
        self.entry_point = None # The entry point defined by CLE
        self.custom_entry_point = None # A custom entry point
        self.deps = None # Needed shared objects (libraries dependencies)

        # MIPS
        self.mips_static_base_addr = None
        self.mips_local_gotno = None
        self.mips_unreftextno = None
        self.mips_gotsym = None
        self.mips_symtabno = None

        if (os.path.exists(binary)):
            self.binary = binary
        else:
            raise CLException("The binary file \"%s\" does not exist :(" %
                              binary)

        l.debug(" [Loading binary object %s]" % self.binary)
        archinfo = Archinfo(binary)
        self.archinfo = archinfo
        arch_name = archinfo.name
        self.bits_per_addr = archinfo.bits_per_addr

        # We use qemu's convention for arch names
        self.arch = archinfo.to_qemu_arch(arch_name)
        self.simarch = archinfo.to_simuvex_arch(arch_name)
        info = self.__call_clextract(binary)
        self.symbols = self.__get_symbols(info)
        self.imports = self.__get_imports(self.symbols)
        self.entry_point = self.__get_entry_point(info)
        self.phdr = self.__get_phdr(info)
        self.deps = self.__get_lib_names(info)
        self.dynamic = self.__get_dynamic(info)
        self.__mips_specifics() # Set MIPS properties
        self.gotaddr = self.__get_gotaddr(self.dynamic) # Add rebase_addr if relocated
        self.jmprel = self.__get_jmprel(info)
        self.endianness = self.__get_endianness(info)
        self.load()

    def get_exec_base_addr(self):
        """
        Return the virtual address of the segment that has the lowest address.
        This is only relevant to executable files, as shared libraries would
        have 0 as their text segment load addresses """

        t = self.get_text_phdr_ent()
        d = self.get_data_phdr_ent()

        if t["vaddr"] > d["vaddr"]:
            return d["vaddr"]
        else:
            return t["vaddr"]

    def get_max_addr(self):
        """ This returns the highest virtual address contained in any loaded
        segment of the binary

        NOTE: relocation is taken into consideration, if it exists. By default,
        rebase_addr is zero.
        When this is called by Cle's loader (Ld), relocations are already in place.
        When this function is called directly, the behavior w.r.t relocation is
        undefined, and depends on whether the caller set rebase_addr to any
        value.
        """

        text = self.get_text_phdr_ent()
        data = self.get_data_phdr_ent()

        m1 = text["vaddr"] + text["memsz"] + self.rebase_addr
        m2 = data["vaddr"] + data["memsz"] + self.rebase_addr

        if m1 > m2:
            return m1
        return m2

    def __get_phdr(self, data):
        """ Get program header table """
        phdr = []
        int_fields = ["offset", "vaddr", "filesz", "memsz", "align"]

        for d in data:
            # Create a new dictionary for each program header of the table
            if d[0] == "phdr":
                idx = 1
                h = {}
                # Add integer fields
                for f in int_fields:
                    h[f] = int(d[idx], 16)
                    idx += 1
                # Type is a string
                h["type"] = d[idx].strip()
                phdr.append(h)
        return phdr

    def __get_shdr(self, data):
        """ Get section header table if present """
        shdr = []
        for i in data:
            # Program headers
            if i[0] == "shdr":
                shdr.append(i)
        return shdr

    def __get_dynamic(self, data):
        """ Get the dynamic section """
        dyn = []
        for i in data:
            ent = {}
            if i[0] == "dyn":
                ent["ptr"] = i[2].strip()
                ent["val"] = i[3].strip()
                ent["tag"] = i[4].strip()
                dyn.append(ent)
        return dyn

    def __get_entry_point(self, data):
        """ Get entry point """
        for i in data:
            if i[0] == "Entry point":
                return int(i[1].strip(), 16)

    def __get_gotaddr(self, dyn):
        """ Address of GOT """
        for i in dyn:
            if i["tag"] == "DT_PLTGOT":
                return int(i["val"], 16)

    def entry(self):
        """ This function mimicks the behavior of the initial Binary class in
        Angr. TODO: abstract things away"""
        if self.custom_entry_point is not None:
            return self.custom_entry_point
        else:
            return self.entry_point

    def set_entry(self, entry_point):
        """ This function mimicks the behavior of the initial Binary class in
        Angr. TODO: abstract things away """
        # Set a custom entry point
        self._custom_entry_point = entry_point

    def __get_endianness(self, data):
        for i in data:
            if i[0] == "Endianness":
                return i[1].strip()

    def get_object_type(self, data):
        """ Get ELF type """
        for i in data:
            if i[0] == "Object_type":
                return i[1]

    def __get_symbols(self, data):
        """ Get symbols addresses """
        symbols = []
        symb = self.__symb(data)
        for i in symb:
            s = {}
            s["addr"] = int(i[1].strip(), 16)
            s["size"] = int(i[2].strip(), 16)
            s["binding"] = i[3].strip()
            s["type"] = i[4].strip()
            s["sh_info"] = i[5].strip()
            s["name"] = i[6].strip()
            symbols.append(s)

        return symbols

    def __symb(self, data):
        """ Extract symbol table entries from Clextract"""
        symb = []
        for i in data:
            # Symbols table
            if i[0] == "symtab":
                symb.append(i)
        return symb

    def __get_jmprel(self, data):
        """ Get the location of the GOT slots corresponding to the addresses of
        relocated symbols (jump targets of the (PLT).
        The story:
        Most arhitectures (including ppc, x86, x86_64 and arm) specify address
        0 for imports (symbols with SHN_UNDEF and STB_GLOBAL) in the symbol
        table, and specify GOT addresses in JMPREL.
        """
        got = {}

        # MIPS does not support this so we need a workaround
        if "mips" in self.arch:
            return self.__get_mips_jmprel()

        for i in data:
            if i[0].strip() == "jmprel":
                # See the output of clextract:
                # i[3] is the symbol name, i[1] is the GOT location
                got[i[3].strip()] = int(i[1].strip(), 16)
        return got

    # What are the external symbols to relocate on MIPS ? And what are their GOT
    # entries ? There is no DT_JMPREL on mips, so let's emulate one
    def __get_mips_jmprel(self):

        symtab_base_idx = self.mips_gotsym # First symbol of symtab that has a GOT entry
        got_base_idx = self.mips_local_gotno  # Index of first global entry in GOT
        gotaddr = self.gotaddr
        got_entry_size = self.bits_per_addr / 8 # How many bytes per slot ?

        jmprel = {}

        count = self.mips_symtabno - self.mips_gotsym # Number of got mapped symbols
        for i in range(0, count):
            sym = self.symbols[symtab_base_idx + i]
            got_idx = got_base_idx + i
            got_slot = gotaddr + (got_idx) * got_entry_size
            jmprel[sym["name"]] = got_slot
        return jmprel

    def relocate_mips_jmprel(self):
        """ After we relocate an ELF object, we also need, in the case of MIPS,
        to relocate its GOT addresses relatively to its static base address """
        if self.rebase_addr == 0:
            raise CLException("Attempting MIPS relocation with rebase_addr = 0")

        delta = self.rebase_addr - self.mips_static_base_addr
        for i,v in self.jmprel.iteritems():
            self.jmprel[i] = v + delta

    def get_text_phdr_ent(self):
        """ Return the entry of the program header table corresponding to the
        text segment"""
        for i in self.phdr:
            if i["type"] == "PT_LOAD" and i["filesz"] == i["memsz"]:
                return i

    def get_data_phdr_ent(self):
        """ Return the enty of the program header table corresponding to the
        data segment"""
        for i in self.phdr:
            # The data segment is smaller in the file than in memory because of
            # the BSS section (not represented in the file as it only contains
            # null bytes)
            if (i["type"] == "PT_LOAD") and (i["filesz"] != i["memsz"]):
                return i

    def __get_imports(self, symbols):
        """ Get imports from symbol table """
        imports = {}
        for i in symbols:
        # Imports are symbols with type SHN_UNDEF in the symbol table
            name = i["name"]
            addr = i["addr"]
            s_info = i["sh_info"]
            binding = i["binding"]
            if (s_info == "SHN_UNDEF" and binding == "STB_GLOBAL"):
                imports[name] = int(addr)
            return imports

    def get_exports(self):
        """ We can basically say that any symbol defined with an address and
        STB_GLOBAL binding is an export
        """
        exports = {}
        for i in self.symbols:
            name = i["name"]
            addr = i["addr"]
            binding = i["binding"]
            info = i["sh_info"]

            # Exports have STB_GLOBAL binding property. TODO: STB_WEAK ?
            if (binding == "STB_GLOBAL" and info != "SHN_UNDEF" ):
                if name in self.imports:
                    raise CLException("Symbol %s at 0x%x is both in imports and "
                                      "exports, something is wrong :(", name, addr)
                exports[name] = addr
        return exports

    #def __get_bfd_arch(self, binary):
    #    """ Get the architecture name using ctypes and cle_bfd.so """
    #    env_p = os.getenv("VIRTUAL_ENV")
    #    lib_p = "lib"
    #    lib = os.path.join(env_p, lib_p, "cle_bfd.so")
    #    if os.path.exists(lib):
    #        self.lib = cdll.LoadLibrary(lib)
    #        self.lib.get_bfd_arch_name.restype = c_char_p
    #        return self.lib.get_bfd_arch_name(binary)
    #    else:
    #        raise CLException("Cannot load cle_bfd.so, invalid path:%s" % lib)

    def __get_lib_names(self, data):
        """ What are the dependencies of the binary ?
        This gets the names of the libraries we should load as well, from the
        dynamic segment """
        deps = []
        for i in data:
            # The first index is the string "needed"
            if i[0] == "needed":
                # The other idexes are the actual dependencies
                for dep in i[1:]:
                    deps.append(dep.strip()) # Remove extra spaces

        l.debug("\t--> binary depends on %s" % repr(deps))
        return deps

    def get_cross_library_path(self):
        """ Returns the path to cross libraries for @arch"""

        arch = self.arch

        if arch == "x86_64":
            return "/usr/x86_64-linux-gnu/"
        elif arch == "ppc":
            return "/usr/powerpc-linux-gnu/"
        elif arch == "mips":
            return "/usr/mips-linux-gnu/"
        elif arch == "arm":
            return "/usr/arm-linux-gnueabi/"
        elif arch == "i386":
            return "/lib32"

    def __call_clextract(self, binary):
        """ Get information from the binary using clextract """
        qemu = self.get_qemu_cmd()
        arch = self.arch
        env_p = os.getenv("VIRTUAL_ENV")
        bin_p = "local/bin/%s" % arch
        lib_p = "local/lib/%s" % arch
        cle = os.path.join(env_p, bin_p, "clextract")

        if (not os.path.exists(cle)):
            raise CLException("Cannot find clextract binary at %s" % cle)

        crosslibs = self.get_cross_library_path()
        # clextract needs libcle which resides in arch/ for each arch
        cmd = [qemu, "-L", crosslibs, "-E", "LD_LIBRARY_PATH=" +
               os.path.join(env_p, lib_p) + ":" + crosslibs, cle, self.binary]

        s = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out = s.communicate()
        err = s.returncode

        # We want to make sure qemu returns correctly before we interpret
        # the output. TODO: we should also get clextract's return code (maybe
        # through an ENV variable ?)
        if (err != 0):
            raise CLException("Qemu returned error %d while running %s :("
                              % (err, " ".join(cmd)))

        else:

            # For some reason all the relevant output resides in out[0]
            data = out[0].splitlines()

            # All the fields are separated by commas, see clextract.c
            s = []
            for i in data:
                s.append(i.split(","))
            return s

    def get_qemu_cmd(self):
        """ Find the right qemu-{cmd} for the binary's architecture """
        cmd = "qemu-%s" % self.arch

        # Check if the command actually exists on the system
        s = subprocess.Popen(["which", cmd], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out = s.communicate()
        err = s.returncode

        # Which returns 0 if the command exists
        if (err != 0):
            raise CLException("Cannot find \"%s\", it does not exist or is not"
                              " in PATH :: %s" % (cmd, out))
        else:
            return cmd

    def load(self):
        """ Load the binary file @binary into memory"""

        text = self.get_text_phdr_ent()
        data = self.get_data_phdr_ent()
        self.__load(text, "text")
        self.__load(data, "data")

        # The data segment is also supposed to contain the BSS section
        self.__load_bss(data)

    def __load_bss(self, data_hdr):
        """ The BSS section does not appear in the binary file, but its size is
        the difference between the binary size and the process memory image size
        """
        size = data_hdr["memsz"] - data_hdr["filesz"]
        off = data_hdr["vaddr"] + data_hdr["filesz"]
        for i in range(off, off + size):
            self.memory[i] = "\x00"

    def __load(self, hdrinfo, name):
        """ Stub to load the text segment """
        if not hdrinfo:
            raise CLException("No program header entry for the %s segment was"
                               " found :(" % name)
        self.load_segment(hdrinfo["offset"], hdrinfo["filesz"],
                          hdrinfo["vaddr"], name)

    def contains_addr(self, addr):
        """ Is @vaddr in one of the binary's segments we have loaded ?
        (i.e., is it mapped into memory ?)
        """
        for i in self.segments:
            if contains_addr(i, addr):
                return True
        return False

    def in_which_segment(self, vaddr):
        """ What is the segment name containing @vaddr ?"""
        for s in self.segments:
            if s.contains_addr(vaddr):
                return s.name
        return None

    def load_segment(self, offset, size, vaddr, name=None):
        """ Load a segment into memory """

        try:
            f = open(self.binary, 'r')
            f.seek(offset)
        except IOError:
            print("\tFile does not exist", self.binary)

        # Fill the memory dict with addr:value
        for i in range(vaddr, vaddr + size):
            # Is something else already loaded at this address ?
            if i in self.memory:
                raise CLException("WTF?? @0x%x Segments overlaping in memory",
                                  i)
            self.memory[i] = f.read(1)

        # Add the segment to the list of loaded segments
        seg = Segment(name, vaddr, size)
        self.segments.append(seg)
        l.debug("\t--> Loaded segment %s @0x%x with size:0x%x" % (name, vaddr,
                                                                size))
    def __mips_specifics(self):
        """ These are specific mips entries of the dynamic table """
        for i in self.dynamic:
            # How many local references in the GOT
            if(i["tag"] == "DT_MIPS_LOCAL_GOTNO"):
                self.mips_local_gotno = int(i["val"].strip(), 16)
            # Index of first externel symbol in GOT
            elif(i["tag"] == "DT_MIPS_UNREFEXTNO"):
                self.mips_unreftextno = int(i["val"].strip(), 16)
            # Static MIPS base address
            elif(i["tag"] == "DT_MIPS_BASE_ADDRESS"):
                self.mips_static_base_addr = int(i["val"].strip(), 16)
            # Index (in the symbol table) of the first symbol that has an
            # entry in the GOT
            elif(i["tag"] == "DT_MIPS_GOTSYM"):
                self.mips_gotsym = int(i["val"].strip(), 16)

            # How many elements in the symbol table
            elif(i["tag"] == "DT_MIPS_SYMTABNO"):
                self.mips_symtabno = int(i["val"].strip(), 16)
                #pdb.set_trace()

class Ld(object):
    """ CLE ELF loader
    The loader loads all the objects and exports an abstraction of the memory of
    the process.
    """
    def __init__(self, binary, force_ida=None):
        """ @path is the path to licle_ctypes.so"""

        self.memory = {} # Dictionary representation of the memory
        self.shared_objects =[] # Executables and libraries
        self.path = binary
        self.main_bin = Elf(binary)
        self.__load_exe()
        #print "mem@ 0x601000: %s" % repr(self.memory[0x601000])
        self.__load_shared_libs()
        #print "mem@ 0x601000: %s" % repr(self.memory[0x601000])
        self.__perform_reloc()
        #print "mem@ 0x601000: %s" % repr(self.memory[0x601000])

    def host_endianness(self):
        if (sys.byteorder == "little"):
            return "LSB"
        else:
            return "MSB"

    def __perform_reloc(self):
        # Main binary
        self.__reloc(self.main_bin)

        # Libraries
        for obj in self.shared_objects:
            self.__reloc(obj)
            # Again, MIPS is a pain...
            if "mips" in obj.arch:
                obj.relocate_mips_jmprel()

    def mem_range(self, a_from, a_to):
        arr = []
        for addr in range(a_from, a_to):
            arr.append(self.memory[addr])
        return "".join(arr)

    def addr_belongs_to_object(self, addr):
        max = self.main_bin.get_max_addr()
        min = self.main_bin.get_exec_base_addr()

        if (addr > min and addr < max):
            return self.main_bin

        for so in self.shared_objects:
            max = so.get_max_addr()
            min = so.rebase_addr
            if (addr > min and addr < max):
                return so

    def min_addr(self):
        """ The minimum base address of any loaded object """

        # Let's start with the main executable
        base = self.main_bin.get_exec_base_addr()

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
                l.debug("\t--> Relocation of %s -> 0x%x [stub@0x%x]" % (symb,
                                                                     uaddr,
                                                                     got_addr))

                baddr = self.__addr_to_bytes(uaddr)
                for i in range(0, len(baddr)):
                    self.memory[got_addr + i] = baddr[i]

            else:
                l.debug("\t--> Cannot locate symbol \"%s\" from SOs" % symb)

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

    def test(self):
        x = self.__addr_to_bytes(int("0xc4f2", 16))
        y = self.__bytes_to_addr(x)

        print x
        print y

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
        """ Load exe into "main memory"""
        for addr, val in self.main_bin.memory.iteritems():
            # There shouldn't be anything in this memory location yet
            if addr in self.memory:
                raise CLException("Something is already loaded at 0x%x" % addr)
            else:
                self.memory[addr] = val

    def __load_shared_libs(self):
        """ Load and rebase shared objects """
        # shared_libs = self.main_bin.deps
        shared_libs = self.ld_so_addr()
        for name, addr in shared_libs.iteritems():
            so = self.__load_so(name)
            if (so):
                self.rebase_lib(so, addr)
                so.rebase_addr = addr
                self.shared_objects.append(so)
            else:
                l.debug("Shared object %s not loaded :(" % name)

    def rebase_lib(self, so, base):
        """ Relocate a shared objet given a base address
        We actually copy the local memory of the object at the new computed
        address in the "main memory" """
        if "mips" in so.arch:
            l.debug("\t--> rebasing the binary object @0x%x (instead of 0x%x)" %
                    (base, so.mips_static_base_addr))
        else:
            l.debug("\t--> rebasing the binary object @0x%x" %base)
        for addr, data in so.memory.iteritems():
            newaddr = addr + base
            #l.debug("Adding %s at 0x%x" % (repr(data), newaddr))
            if newaddr in self.memory:
                raise CLException("Soemthing is already loaded at 0x%x" % newaddr)
            else:
                self.memory[newaddr] = data

    def ld_so_addr(self):
        """ Use LD_AUDIT to find object dependencies and relocation addresses"""

        qemu = self.main_bin.get_qemu_cmd()
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

        cross_libs = self.main_bin.get_cross_library_path()
        ld_path = ld_path + ":" + cross_libs

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
                l.debug(" (Will load %s @ 0x%x)" % (o,a) )

            l.debug("---")
            os.remove(log)
            return libs

        else:
            raise CLException("Could not find library dependencies using ld."
                " The log file '%s' does not exist, did qemu fail ? Try to run "
                              "`%s` manually to check" % (log, " ".join(cmd)))

    def __load_so(self, soname):
        """ Load a shared object into memory """
        # Soname can be a path or just the name if the library, in which case we
        # search for it in known paths.
        if (not os.path.exists(soname)):
            path = self.__search_so(soname)
            soname = path

        if (soname == None):
            raise CLException("Could not find shared object %s :(" %
                                  repr(soname))
        else:
            so = Elf(soname)
            return so

    def __search_so(self, soname):
        """ Looks for a shared object given its filename"""

        # Normally we should not need this as LD knows everything already. But
        # in case we need to look for stuff manually...
        loc = []
        loc.append(os.getenv("LD_LIBRARY_PATH"))
        loc.append(os.path.dirname(self.path))
        loc.append(self.main_bin.get_cross_library_path())

        libname = os.path.basename(soname)

        for ld_path in loc:
            if not ld_path: continue
            for s_path, s_dir, s_file in os.walk(ld_path):
                sopath = os.path.join(s_path,libname)
                #l.debug("\t--> Trying %s" % sopath)
                if os.path.exists(sopath):
                    l.debug("-->Found %s" % sopath)
                    return sopath



