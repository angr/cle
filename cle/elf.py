from ctypes import *
import os
import logging
from .archinfo import ArchInfo
import subprocess
from .clexception import CLException

l = logging.getLogger("cle.elf")

class Segment(object):
    """ Simple representation of an ELF file segment"""
    def __init__(self, name, vaddr, size, offset=None):
        self.vaddr = vaddr
        self.size = size
        self.offset = offset
        self.name = name

    def contains_addr(self, addr):
            return ((addr > self.vaddr) and (addr < self.vaddr + self.size))


class Elf(object):
    """ Representation of loaded Elf binaries """
    def __init__(self, binary, load=True):

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
        archinfo = ArchInfo(binary)
        self.archinfo = archinfo
        arch_name = archinfo.name
        self.bits_per_addr = archinfo.bits

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

        if load == True:
            self.load()

    def get_min_addr(self):
        """
        Return the virtual address of the segment that has the lowest address.
        WARNING: this is calculated BEFORE rebasing the binaries, therefore,
        this is only relevant to executable files, as shared libraries should always
        have 0 as their text segment load addresseses.
        """

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
        self.custom_entry_point = entry_point

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
            if ((s_info == "SHN_UNDEF") and (binding == "STB_GLOBAL")):
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

    def __call_clextract(self, binary):
        """ Get information from the binary using clextract """
        qemu = self.archinfo.get_qemu_cmd()
        arch = self.arch
        env_p = os.getenv("VIRTUAL_ENV", "/")
        bin_p = "local/bin/%s" % arch
        lib_p = "local/lib/%s" % arch
        cle = os.path.join(env_p, bin_p, "clextract")

        if (not os.path.exists(cle)):
            raise CLException("Cannot find clextract binary at %s" % cle)

        crosslibs = self.archinfo.get_cross_library_path()
        ld_libs = self.archinfo.get_cross_ld_path()
        # clextract needs libcle which resides in arch/ for each arch
        cmd = [qemu, "-L", crosslibs, "-E", "LD_LIBRARY_PATH=" +
               os.path.join(env_p, lib_p) + ":" + ld_libs
               , cle, self.binary]

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

    def is_thumb(self,addr):
        """ Is the address @addr in thumb mode ? """
        if not "arm" in self.arch:
            raise CLException("Dude, thumb mode is on ARM!")

        """ Is the entry point in ARM or Thumb mode ?
        If the first bit of the entry point's address is 1, then Thumb.
        If it is 00, then ARM. Check page 46 of this document for details:
        http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf
        """
        if addr == self.entry_point:
            t_bit = addr
            while t_bit > 2:
                t_bit >> 1
                return t_bit & 0b1
        else:
            raise CLException("Runtime thumb mode detection not implemented")

    def function_name(self, addr):
        """ Return the name of the function containing @addr"""
        l.debug("TODO: implement this")
        return
