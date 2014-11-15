import os
import logging
import subprocess
from .clexception import CLException
from .abs_obj import AbsObj

l = logging.getLogger("cle.elf")


class Segment(object):
    """ Simple representation of an ELF file segment"""
    def __init__(self, name, vaddr, size, offset=None):
        self.vaddr = vaddr
        self.size = size
        self.offset = offset
        self.name = name

    def contains_addr(self, addr):
            return ((addr >= self.vaddr) and (addr < self.vaddr + self.size))

    def contains_offset(self, offset):
        return ((offset >= self.offset) and (offset < self.offset + self.size))

    def addr_to_offset(self, addr):
        return addr - self.vaddr + self.offset

    def offset_to_addr(self, offset):
        return offset - self.offset + self.vaddr


class Elf(AbsObj):
    """ Representation of loaded Elf binaries """

    def __init__(self, *args, **kwargs):
        """ Initialization of the Elf object.
        This is called by the constructor of the parent class
        """

        # Call the constructor of AbsObj
        super(Elf, self).__init__(*args, **kwargs)

        # Shall we load the binary ? Yes by default
        load = True if 'load' not in kwargs else False

        # MIPS
        self.mips_static_base_addr = None
        self.mips_local_gotno = None
        self.mips_unreftextno = None
        self.mips_gotsym = None
        self.mips_symtabno = None
        #self.segments = None # Loaded segments

        info = self.__call_clextract(self.binary)

        # TODO: fix this
        self.elfflags = self.__get_elf_flags(info)
        self.archinfo.elfflags = self.elfflags
        ##

        self.symbols = self.__get_symbols(info)
        self.strtab = self.__get_strtab(info)
        self.strtab_vaddr = self.__get_strtab_vaddr(info)
        self.imports = self.__get_imports(self.symbols)
        self.entry_point = self.__get_entry_point(info)
        self.linking = self.__get_linking_type(info)
        self.phdr = self.__get_phdr(info)
        self.deps = self.__get_lib_names(info)
        self.dynamic = self.__get_dynamic(info)
        self.__mips_specifics() # Set MIPS properties
        self.endianness = self.__get_endianness(info)
        self.resolved_imports = [] # Imports successfully resolved, i.e. GOT slot updated

        # Stuff static binaries don't have
        if self.linking == "dynamic":
            self.gotaddr = self.__get_gotaddr(self.dynamic) # Add rebase_addr if relocated
            self.jmprel = self.__get_jmprel(info)

        if load is True:
            self.load()

        self._ppc64_abiv1_entry_fix()

    def get_min_addr(self):
        """
        Return the virtual address of the segment that has the lowest address.
        WARNING: this is calculated BEFORE rebasing the binaries, therefore,
        this is only relevant to executable files, as shared libraries should always
        have 0 as their text segment load addresseses.
        """

        t = self.get_text_phdr_ent()
        d = self.get_data_phdr_ent()

        # If there is no data segment
        if d is None:
            return t["vaddr"]

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

        # if there is no data segment
        if data is None:
            return text["vaddr"] + text["memsz"] + self.rebase_addr

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

    def __get_elf_flags(self, data):
        for i in data:
            if i[0] == "Flags":
                return int(i[1].strip(), 16)

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

    def __strtab(self, data):
        """ Extract symbol table info from Clextract """
        strtab = []
        for i in data:
            if i[0] == "strtab":
                strtab.append(i)
        return strtab

    def __get_strtab(self, data):
        """
        Returns {offset_in_string_table : string}
        """
        strtab = {}
        for i in self.__strtab(data):
            offset = i[1].strip()
            name = i[2].strip()
            strtab[offset] = name
        return strtab

    def __get_strtab_vaddr(self, data):
        """
        Returns the virtual address of the strtab.
        On PIE binaries, you might want to add the base address to it (TODO: check that)
        """
        for i in data:
            if i[0] == "strtab_vaddr":
                return int(i[1].strip(),16)

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

    def __get_mips_jmprel(self):
        """
        What are the external symbols to relocate on MIPS ? And what are their GOT
        entries ? There is no DT_JMPREL on mips, so let's emulate one
        """

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

    def __get_linking_type(self, data):
        for i in data:
            if i[0] == "Linking":
                return i[1].strip()
        raise CLException("We could not get any linking information from the "
                          "binary, this should not happen")

    def relocate_mips_jmprel(self):
        """ After we relocate an ELF object, we also need, in the case of MIPS,
        to relocate its GOT addresses relatively to its static base address.
        Note: according to the Elf specification, this ONLY applies to shared objects
        """

        # This should not be called for non rebased binaries (i.e., main
        # binaries)
        if self.rebase_addr == 0:
            raise CLException("Attempting MIPS relocation with rebase_addr = 0")

        # Here, we shift all GOT addresses (the slots, not what they contain)
        # by a delta. This is because the MIPS compiler expected us to load the
        # binary at self.mips_static_base_addr)
        delta = self.rebase_addr - self.mips_static_base_addr
        l.info("Relocating MIPS GOT entries - static base addr is 0%x, acutal "
               "base addr is 0x%x" % (self.mips_static_base_addr, self.rebase_addr))
        for i,v in self.jmprel.iteritems():
            self.jmprel[i] = v + delta

    def _get_load_phdr_ent(self):
        """ Get entries of the program header table that correspond to PT_LOAD
        segments
        """
        loadable = []
        for i in self.phdr:
            if i["type"] == "PT_LOAD":
                loadable.append(i)
        return loadable

    def get_text_phdr_ent(self):
        """ Return the entry of the program header table corresponding to the
        text segment. This is the first PT_LOAD segment we encounter"""
        load = self._get_load_phdr_ent()
        if len(load) == 1:
            return load[0]
        # Return the segment with the lowest vaddr
        return load[0] if load[0]["vaddr"] < load[1]["vaddr"] else load[1]

    def get_data_phdr_ent(self):
        """ Return the enty of the program header table corresponding to the
        data segment.
        Note: the DATA segment is often smaller on disk than it is in memory because
        of the BSS segment, but it is not always the case so we can't use that
        as a valid heuristic
        """
        load = self._get_load_phdr_ent()
        if len(load) == 1:
            return None

        # Return the segment with the highest vaddr
        return load[0] if load[0]["vaddr"] > load[1]["vaddr"] else load[1]

    def __get_imports(self, symbols):
        """ Get imports from symbol table """
        imports = {}
        for i in symbols:
        # Imports are symbols with type SHN_UNDEF in the symbol table
            name = i["name"]
            addr = i["addr"]
            s_info = i["sh_info"]
            binding = i["binding"]
            if ((s_info == "SHN_UNDEF") and (binding == "STB_GLOBAL" or binding
                                             == "STB_WEAK")):
                imports[name] = int(addr)
        return imports

    def get_exports(self):
        """ Symbol defined with an address and with STB_GLOBAL or STB_WEAK
        binding are exports.
        """
        exports = {}
        for i in self.symbols:
            name = i["name"]
            addr = i["addr"]
            binding = i["binding"]
            info = i["sh_info"]

            # Exports are defined symbols with STB_GLOBAL or STB_WEAK binding properties.
            if (info != 'SHN_UNDEF'):
                if (binding == "STB_GLOBAL" or binding == "STB_WEAK"):
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
        arch = self.archinfo.get_unique_name()
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
        if (err != 0 and err !=1): # For some reasons, it returns 1 sometimes on success
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
        if data is not None:
            self.__load(data, "data")
            # The data segment is also supposed to contain the BSS section
            self.__load_bss(data)
        else:
            l.warning("There is NO data segment in this binary !")

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

        WARNING: in the case of relocatable objects (e.g., libraries), this
        function works with relative addresses (wrt the start of the object).
        Remember that statically, the Elf headers define a virtual address of 0
        for relocatable objects.

        If you try to use this function with a runtime address of a relocated
        object, you should consider substracting the rebase_addr value to @addr
        beforehands.
        """
        for i in self.segments:
            if i.contains_addr(addr):
                return True
        return False

    def in_which_segment(self, vaddr):
        """ What is the segment name containing @vaddr ?"""
        for s in self.segments:
            if s.contains_addr(vaddr):
                return s.name
        return None

    def get_segment(self, vaddr):
        """ Returns the segment that contains @vaddr """
        for s in self.segments:
            if s.contains_addr(vaddr):
                return s

    def addr_to_offset(self, addr):
        for s in self.segments:
            if s.contains_addr(addr):
                return s.addr_to_offset(addr)
        return None

    def offset_to_addr(self, offset):
        for s in self.segments:
            if s.contains_offset(offset):
                return s.offset_to_addr(offset)

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
        seg = Segment(name, vaddr, size, offset)
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
        If it is 00, then ARM. Check page 16 of this document for details:
        http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf
        """
        if addr == self.entry_point:
            return (addr & 1) == 1
        else:
            raise CLException("Runtime thumb mode detection not implemented")

    def get_local_functions(self):
        """
        We consider local functions those that are not SHN_UNDEF in the symbol table,
        and that have an address inside the binary.
        This returns a dict indexed by *addresses*
        """
        local_symbols={}
        for e in self.symbols:
            if e['sh_info'] != 'SHN_UNDEF':
                if self.contains_addr(e['addr']):
                    addr = e['addr']
                    local_symbols[addr] = e['name']

        return local_symbols

    def get_global_symbols(self):
        """
        These are (non-functions) global symbols exposed in the symbol table,
        such as stderr, __progname and stuff
        """
        glob={}
        for e in self.symbols:
            if e['binding'] == 'STB_GLOBAL' and e['type'] == 'STT_OBJECT':
                name = e['name']
                glob[name] = e['addr']
        return glob

    def function_name(self, addr):
        """
        Try to guess whether @addr is inside the code of a local function.
        """

        # The Elf class works with static non relocated addresses
        addr = addr - self.rebase_addr

        if not self.contains_addr(addr):
            return None

        local = self.get_local_functions()
        if len(local) == 0:
            return None

        addrs = local.keys()
        addrs.sort()

        # Let's add the upper bound of the text segment to this list.
        addrs.append(self.segments[0].vaddr + self.segments[0].size)

        if addr < min(addrs) or addr > max(addrs):
            return None

        for i in range(0, len(addrs) - 1):
            if addr >= addrs[i] and addr < addrs[i+1]:
                r = addrs[i]
                return local[r]

    def get_plt_stub_addr(self, name):
        """
        Get the address of the PLT stub for function @name.
        Functions must have a know GOT entry in self.jmprel
        """
        if name not in self.jmprel.keys():
            raise CLException("%s does not figure in the GOT")

        # What's in the got slot for @name ?
        got = self.jmprel[name]
        fetch = self.memory.read_bytes(got, self.archinfo.bits/8)

        """
        This is the address of the next second instruction in the PLT stub
        This is hackish but it works
        """
        addr = self.archinfo.bytes_to_addr(fetch)

        if self.archinfo.name == "i386:x86-64":
            # 0x6 is the size of the plt's jmpq instruction in x86_64
            return addr - 0x6
        else:
            raise CLException("Not implemented yet.")
