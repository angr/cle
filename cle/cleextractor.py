import os
import logging
import subprocess
from .errors import CLEError, CLEOperationError, CLEInvalidBinaryError
from .absobj import Segment
from .metaelf import MetaELF

l = logging.getLogger("cle.cleextractor")

class CLEExtractor(MetaELF):
    """
    Representation of loaded (but NOT rebased) Elf binaries. What you see here
    is what we get from the Elf file by snooping on the actual loading process
    we run in qemu.

    For shared objects with a base address (aka shared libraries) as well as PIE
    binaries, any address you see here means an offset in the binary, as opposed
    to the actual virtual addresses where it's going to be loaded at once
    rebased. In other words, the base address is always 0.

    For non PIE executables (i.e., non libraries), addresses you see are the
    default virtual addresses where stuff is loaded by the loader.

    Other than that, if you want to deal with a full address space, and with
    rebased and relocated addresses, use cle.Ld.
    """

    def __init__(self, *args, **kwargs):
        """ Initialization of the Elf object.
        This is called by the constructor of the parent class
        """
        raise CLEError("The CLEExtract backend is unsupported")

        # Call the constructor of AbsObj
        super(CLEExtractor, self).__init__(*args, **kwargs)

        # Shall we load the binary ? Yes by default
        load = True if 'load' not in kwargs else False

        # MIPS
        self.mips_static_base_addr = None
        self.mips_local_gotno = None
        self.mips_unreftextno = None
        self.mips_gotsym = None # index of first entry of dynsym that is part of GOT
        self.mips_symtabno = None # number of entries in the .dynsym section
        #self.segments = None # Loaded segments

        self.tls_init_image = None

        info = self._call_ccle()

        self.symbols = self._get_symbols(info)
        self.s_symbols = self._get_symbols(info, static=True)
        self.strtab = self._get_strtab(info)
        self.strtab_vaddr = self._get_strtab_vaddr(info)
        self.imports = self._get_imports(self.symbols)
        self.exports = self._get_exports()
        self._elf_entry = self._get_entry_point(info) # Elf entry point
        self.linking = self._get_linking_type(info)
        self.phdr = self._get_phdr(info)
        self.tdata, self.tbss = self._get_tls_addresses()
        self.deps = self._get_lib_names(info)
        self.dynamic = self._get_dynamic(info)
        self._mips_specifics() # Set MIPS properties

        self.endianness = self._get_endianness(info)
        self.resolved_imports = {} # Imports successfully resolved, i.e. GOT slot updated
        self.object_type = self.get_object_type(info)
        self.raw_reloc = []
        self.jmprel={}

        # Stuff static binaries don't have
        # TODO: some static binaries may have relocations
        if self.linking == "dynamic":
            l.debug("TODO: check status of relocations on static libc")
            self.rela_type = self._get_rela_type(info)
            self.raw_reloc = self._get_raw_reloc(info)
            self._dyn_gotaddr = self._get_gotaddr(self.dynamic) # Add rebase_addr if relocated
            self.global_reloc = self._get_global_reloc()
            self.s_a_reloc = self._get_s_a_reloc()
            self.relative_reloc = self._get_relative_reloc()
            self.copy_reloc = self._get_copy_reloc()
            self.tls_mod_reloc = self._get_tls_mod_reloc()
            self.tls_offset_reloc = self._get_tls_offset_reloc()
            self.jmprel = self._get_jmprel(info)
        else:
            self._dyn_gotaddr = None
            self.rela_type = None
            self._dyn_gotaddr = None
            self.global_reloc = { }
            self.s_a_reloc = [ ]
            self.relative_reloc = [ ]
            self.copy_reloc = [ ]

        self.sections = self._get_static_sections(info)

        if load is True:
            self.load()

        self.plt = self._load_plt()
        self._ppc64_abiv1_entry_fix()

    @staticmethod
    def _get_phdr(data):
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

    @staticmethod
    def _get_shdr(data):
        """ Get section header table if present """
        shdr = []
        for i in data:
            # Program headers
            if i[0] == "shdr":
                shdr.append(i)
        return shdr

    @staticmethod
    def _get_dynamic(data):
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

    @staticmethod
    def _get_entry_point(data):
        """ Get entry point """
        for i in data:
            if i[0] == "Entry point":
                return int(i[1].strip(), 16)

    @staticmethod
    def _get_gotaddr(dyn):
        """ Address of GOT """
        for i in dyn:
            if i["tag"] == "DT_PLTGOT":
                return int(i["val"], 16)

    @property
    def entry(self):
        """ This function mimicks the behavior of the initial Binary class in
        Angr. TODO: abstract things away"""
        if self.custom_entry_point is not None:
            return self.custom_entry_point
        else:
            return self._elf_entry

    def set_entry(self, entry_point):
        """ This function mimicks the behavior of the initial Binary class in
        Angr. TODO: abstract things away """
        # Set a custom entry point
        self.custom_entry_point = entry_point

    @staticmethod
    def _get_endianness(data):
        for i in data:
            if i[0] == "Endianness":
                return i[1].strip()

    @staticmethod
    def _get_elf_flags(data):
        for i in data:
            if i[0] == "Flags":
                return int(i[1].strip(), 16)

    @staticmethod
    def get_object_type(data):
        """ Get ELF type """
        for i in data:
            if i[0] == "Object type":
                return i[1].strip()

    def _get_symbols(self, data, static=False):
        """ Get symbols addresses """
        symbols = []
        symb = self._symb(data, static=static)
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

    @staticmethod
    def _symb(data, static=False):
        """ Extract symbol table entries from ccle"""
        symb = []
        if static:
            ln = "s_symtab"
        else:
            ln = "symtab"

        for i in data:
            # Symbols table
            if i[0] == ln:
                symb.append(i)
        return symb

    @staticmethod
    def _strtab(data):
        """ Extract symbol table info from ccle """
        strtab = []
        for i in data:
            if i[0] == "strtab":
                strtab.append(i)
        return strtab

    def _get_strtab(self, data):
        """
        Returns {offset_in_string_table : string}
        """
        strtab = {}
        for i in self._strtab(data):
            offset = int(i[1].strip(), 16)
            name = i[2].strip()
            strtab[offset] = name
        return strtab

    @staticmethod
    def _get_strtab_vaddr(data):
        """
        Returns the virtual address of the strtab.
        On PIE binaries, you might want to add the base address to it (TODO: check that)
        """
        for i in data:
            if i[0] == "strtab_vaddr":
                return int(i[1].strip(),16)

    def _get_jmprel(self, data):
        """ Get the location of the GOT slots corresponding to the addresses of
        relocated symbols (jump targets of the (PLT).
        The story:
        Most arhitectures (including ppc, x86, x86_64 and arm) specify address
        0 for imports (symbols with SHN_UNDEF and STB_GLOBAL) in the symbol
        table, and specify GOT addresses in JMPREL.
        """
        got = {}

        index = 0
        for i in data:
            if i[0].strip() == "jmprel":
                # See the output of ccle:
                # i[2] is the symbol name, i[1] is the GOT location
                name = i[2].strip()
                if name == '':
                    name = "CLE_JMP_UNKN_" + str(index)
                    index = index + 1
                got[name] = int(i[1].strip(), 16)

        # old MIPS ABIS don't not support jmprel so we need a workaround
        #TODO: we should probably try to find out which versions of the MIPS ABI are affected
        # as it might impact the behavior of other things...
        if len(got) == 0 and self.arch.name == 'MIPS32':
           got = self._get_mips_jmprel()

        return got

    def _get_raw_reloc(self, data):
        reloc = []
        for i in data:
            if i[0].strip() == "reloc":
                if self._get_rela_type(data) == "DT_RELA":
                    # (offset, name, reloc_type, addend)
                    reloc.append( (int(i[1].strip(), 16), i[2].strip(), int(i[3].strip(),10), int(i[4].strip(),16) ) )
                elif self._get_rela_type(data) == "DT_REL":
                    # (offset, name, reloc_type)
                    reloc.append( (int(i[1].strip(), 16), i[2].strip(), int(i[3].strip(),10)))
        return reloc

    @staticmethod
    def _get_rela_type(data):
        """
        Elf relocation structure type, DT_RELA or DT_REL
        DT_RELA has extra information (addend)
        """
        for i in data:
            if i[0].strip() == "rela_type":
                return i[1].strip()

    def _get_global_reloc(self):
        """
        Get dynamic relocation information for global data.
        Returns: a dict {name:offset}
        """

        if self.arch.name == "MIPS32":
            return self._get_mips_global_reloc()
        reloc = {}

        # 6 : R_386_GLOB_DAT - these are GOT entries to update

        raw_reloc = self.raw_reloc

        # raw reloc: (offset, name, reloc_type)
        for t in raw_reloc:
            if t[2] in self.arch.reloc_s:
                reloc[t[1]] = t[0]
                if t[1] == '':
                    raise CLEOperationError("Empty name in global data reloc, this is a bug\n")
        return reloc

    def _get_s_a_reloc(self):
        """
        Get dynamic relocation information for relocation type S+A (see Archinfo).
        Returns: a dict {name:offset}
        """

        raw_reloc = self.raw_reloc
        reloc_type = self.arch.reloc_s_a
        if reloc_type is None:
            return []

        reloc = []
        # raw reloc: (offset, name, reloc_type)
        for t in raw_reloc:
            if t[2] in reloc_type:
                if self.rela_type == "DT_RELA":
                # Tuple (name, offset, addend)
                    reloc.append((t[1], t[0], t[3]))
                else:
                    reloc.append((t[1], t[0]))

                if t[1] == '':
                    raise CLEOperationError("Empty name in '32' data reloc, this is a bug\n")
        return reloc

    def _get_relative_reloc(self):
        """
        Get dynamic relative relocation information.
        We typically don't have these guys' names.
        Returns: a list of tuples (offset, name)
        """
        reloc = []

        # 8 : R_386_RELATIVE - We need to add the load address to the offset
        # when relocating

        raw_reloc = self.raw_reloc
        for t in raw_reloc:
            if t[2] in self.arch.reloc_b_a:
                if self.rela_type == "DT_RELA":
                    #(offset, addend)
                    reloc.append((t[0], t[3]))
                else:
                    #(offset)
                    reloc.append((t[0],)) # Tuples need a comma
        return reloc

    def _get_copy_reloc(self):
        """
        Copy actual data instead of its address when relocating.
        """

        reloc =[]

        raw_reloc = self.raw_reloc
        for t in raw_reloc:
            if t[2] in self.arch.reloc_copy:
                    reloc.append((t[0], t[1]))
        return reloc

    def _get_tls_mod_reloc(self):
        """
        Find relocs for the TLS "module ID".
        returns: a list of offsets
        """
        tls_mod_relocs = self.arch.reloc_tls_mod_id
        return [t[0] for t in self.raw_reloc if t[2] in tls_mod_relocs]

    def _get_tls_offset_reloc(self):
        """
        Find relocs for offsets into each TLS block.
        returns: a dict {offset_into_obj: offset_into_tls_block}
        """
        tls_offset_relocs = self.arch.reloc_tls_offset
        return {t[0]: t[3] for t in self.raw_reloc if t[2] in tls_offset_relocs}

    def _get_mips_external_reloc(self):
        """
        What are the external symbols to relocate on MIPS ? And what are their GOT
        entries ? Those can be jmp or global data relocations. In fact, these
        are all the GOT entries corresponding to external symbols (note that, on
        MIPS, there are also GOT entries for local symbols).
        """

        if len(self.symbols) == 0:
            return []

        symtab_base_idx = self.mips_gotsym # First symbol of symtab that has a GOT entry
        got_base_idx = self.mips_local_gotno  # Index of first global entry in GOT
        gotaddr = self.gotaddr
        got_entry_size = self.arch.bytes # How many bytes per slot ?

        rel = {}

        count = self.mips_symtabno - self.mips_gotsym # Number of got mapped symbols
        l.debug("Relocating %d external GOT entries", count)
        for i in range(count):
            sym = self.symbols[symtab_base_idx + i]
            got_idx = got_base_idx + i
            got_slot = gotaddr + (got_idx) * got_entry_size
            rel[sym["name"]] = got_slot
        return rel

    def _get_mips_jmprel(self):
        """There is no DT_JMPREL on mips, so let's emulate one """

        relocs = self._get_mips_external_reloc()
        jmprel = {}
        for k,v in relocs.iteritems():
            if k in self.imports:
                jmprel[k] = v
        return jmprel

    def _get_mips_global_reloc(self):
        """
        Mips specific crap
        """
        reloc = {}
        for k,v in self._get_mips_external_reloc().iteritems():
            if k in self.global_symbols or k in self.global_functions:
                reloc[k] = v
        return reloc

    @staticmethod
    def _get_linking_type(data):
        for i in data:
            if i[0] == "Linking":
                return i[1].strip()
        raise CLEOperationError("We could not get any linking information from the "
                                "binary, this should not happen")


    def _get_tls_addresses(self):
        for e in self.phdr:
            if e['type'] == 'PT_TLS':
                return int(e['vaddr']), int(e['vaddr']) + int(e['filesz'])
        return None, None

    def _get_load_phdr_ent(self):
        """ Get entries of the program header table that correspond to PT_LOAD
        segments
        """
        loadable = []
        for i in self.phdr:
            if i["type"] == "PT_LOAD":
                loadable.append(i)
        return loadable

    @staticmethod
    def _get_static_sections(data):
        """
        Get information from Elf sections (as opposed to segments).
        Sections are used by the static linker, and are not required by the
        loader nor the dynamic linker. There is no guarantee that such sections
        are present in the binary, those can be stripped.
        """
        sections={}
        for i in data:
            if i[0].strip() == "shdr":
                name = i[1].strip()
                s={}
                s["f_offset"] = int(i[2].strip(),16)
                s["addr"] = int(i[3].strip(), 16)
                s["size"] = int(i[4].strip(), 16)
                s["type"] = i[5].strip()
                sections[name] = s

        return sections

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

    def get_tls_phdr_ent(self):
        """ Return the entry of the program header table corresponding to the
        TLS segment. Returns None if not found. """
        for e in self.phdr:
            if e['type'] == 'PT_TLS':
                return e
        return None

    @staticmethod
    def _get_imports(symbols):
        """ Get function imports from symbol table. Note that the address here might have
        different meanings depending on the architecture."""
        imports = {}
        for i in symbols:
        # Imports are symbols with type SHN_UNDEF in the symbol table
            name = i["name"]
            addr = i["addr"]
            s_info = i["sh_info"]
            binding = i["binding"]
            stype = i["type"]
            if ((s_info == "SHN_UNDEF") and (binding == "STB_GLOBAL" or binding
                                             == "STB_WEAK") and stype == "STT_FUNC"):
                imports[name] = int(addr)
        return imports

    def _get_exports(self):
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
            if info != 'SHN_UNDEF':
                if binding == "STB_GLOBAL" or binding == "STB_WEAK":
                    if name in self.imports:
                        raise CLEInvalidBinaryError("Symbol %s at 0x%x is both in imports and "
                                                    "exports, something is wrong :(", name, addr)
                    exports[name] = addr
        return exports

    @staticmethod
    def _get_lib_names(data):
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

        l.debug("\t--> binary depends on %s", repr(deps))
        return deps

    def _call_ccle(self):
        """ Get information from the binary using ccle """
        qemu = 'qemu-%s' % self.arch.qemu_name
        arch = self.arch.name.lower()
        env_p = os.getenv("VIRTUAL_ENV", "/")
        bin_p = "local/bin/%s" % arch
        lib_p = "local/lib/%s" % arch
        cle = os.path.join(env_p, bin_p, "ccle")

        if not os.path.exists(cle):
            raise CLEOperationError("Cannot find ccle binary at %s" % cle)

        crosslibs = ':'.join(self.arch.lib_paths)
        if self.arch.name in ('AMD64', 'X86'):
            ld_libs = self.arch.lib_paths
        elif self.arch.name == 'PPC64':
            ld_libs = map(lambda x: x + 'lib64/', self.arch.lib_paths)
        else:
            ld_libs = map(lambda x: x + 'lib/', self.arch.lib_paths)
        ld_libs = ':'.join(ld_libs)
        # ccle needs libcle which resides in arch/ for each arch
        cmd = [qemu, "-L", crosslibs, "-E", "LD_LIBRARY_PATH=" +
               os.path.join(env_p, lib_p) + ":" + ld_libs
               , cle, self.binary]

        s = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out = s.communicate()
        err = s.returncode

        # We want to make sure qemu returns correctly before we interpret
        # the output. TODO: we should also get ccle's return code (maybe
        # through an ENV variable ?)
        if err != 0:
            raise CLEOperationError("Qemu returned error %d while running %s :("
                                    % (err, " ".join(cmd)))

        else:

            # For some reason all the relevant output resides in out[0]
            data = out[0].splitlines()

            # All the fields are separated by commas, see ccle.c
            s = []
            for i in data:
                s.append(i.split(','))
            return s

    def load(self):
        """ Load the binary file @binary into memory"""

        text = self.get_text_phdr_ent()
        data = self.get_data_phdr_ent()
        tls = self.get_tls_phdr_ent()

        self._load(text, "text")
        if data is not None:
            self._load(data, "data")
            # The data segment is also supposed to contain the BSS section
            self._load_bss(data)
        else:
            l.warning("There is NO data segment in this binary !")

        if tls is not None:
            self._load_tls(tls)
        else:
            self.tls_init_image = ""

    def _load_bss(self, data_hdr):
        """ The BSS section does not appear in the binary file, but its size is
        the difference between the binary size and the process memory image size
        """
        size = data_hdr["memsz"] - data_hdr["filesz"]
        off = data_hdr["vaddr"] + data_hdr["filesz"]
        self.memory.add_backer(off, '\0'*size)

    def _load(self, hdrinfo, name):
        """ Stub to load the text segment """
        if not hdrinfo:
            raise CLEInvalidBinaryError("No program header entry for the %s segment was"
                                        " found :(" % name)
        self.load_segment(hdrinfo["offset"], hdrinfo["filesz"],
                          hdrinfo["memsz"], hdrinfo["vaddr"], name)

    def _load_tls(self, hdrinfo):
        with open(self.binary, 'rb') as f:
            f.seek(hdrinfo['offset'])

            bss_size = hdrinfo['memsz'] - hdrinfo['filesz']
            self.tls_init_image = f.read(hdrinfo['filesz']) + '\x00'*bss_size

    def load_segment(self, offset, size, memsize, vaddr, name=None):
        """ Load a segment into memory """

        try:
            f = open(self.binary, 'r')
        except IOError:
            print("\tFile does not exist", self.binary)

        # Fill the memory dict with addr:value
        f.seek(offset)
        self.memory.add_backer(vaddr, f.read(size))

        # Add the segment to the list of loaded segments
        seg = Segment(vaddr, memsize, size, offset)
        self.segments.append(seg)
        l.debug("\t--> Loaded segment %s @0x%x with size:0x%x", name, vaddr, size)

    def _mips_specifics(self):
        """ These are specific mips entries of the dynamic table """
        for i in self.dynamic:
            # How many local references in the GOT
            if i["tag"] == "DT_MIPS_LOCAL_GOTNO":
                self.mips_local_gotno = int(i["val"].strip(), 16)
            # Index of first externel symbol in GOT
            elif i["tag"] == "DT_MIPS_UNREFEXTNO":
                self.mips_unreftextno = int(i["val"].strip(), 16)
            # Static MIPS base address
            elif i["tag"] == "DT_MIPS_BASE_ADDRESS":
                self.mips_static_base_addr = int(i["val"].strip(), 16)
            # Index (in the symbol table) of the first symbol that has an
            # entry in the GOT
            elif i["tag"] == "DT_MIPS_GOTSYM":
                self.mips_gotsym = int(i["val"].strip(), 16)

            # How many elements in the symbol table
            elif i["tag"] == "DT_MIPS_SYMTABNO":
                self.mips_symtabno = int(i["val"].strip(), 16)

    @staticmethod
    def _global_symbols(symbols):
        """
        These are (non-functions) global symbols exposed in the symbol table,
        such as stderr, __progname and stuff
        """
        glob = {}

        for e in symbols:
            if e['binding'] == 'STB_GLOBAL' and e['type'] == 'STT_OBJECT':
                name = e['name']
                glob[name] = e['addr']
        return glob

    @staticmethod
    def _local_symbols(symbols):
        """
        These are (non-functions) global symbols exposed in the symbol table,
        such as stderr, __progname and stuff
        """
        loc = {}

        for e in symbols:
            if e['binding'] == 'STB_LOCAL' and e['type'] == 'STT_OBJECT':
                name = e['name']
                loc[name] = e['addr']
        return loc

    @staticmethod
    def _local_functions(symbols):
        loc={}
        for e in symbols:
            if e['type'] == 'STT_FUNC' and e['sh_info'] != 'SHN_UNDEF':
                if e['addr'] == 0:
                    raise CLEInvalidBinaryError("Local symbol with address 0")
                name = e['name']
                loc[name] = e['addr']
        return loc

    @staticmethod
    def _global_functions(symbols):
        """
        Global functions that are defined in the binary
        We use it to relocate MIPS stuff while making sure it doesn't interfer with JMPREL
        """
        loc={}
        for e in symbols:
            if e['type'] == 'STT_FUNC' and e['binding'] == 'STB_GLOBAL' and\
            e['sh_info'] != 'SHN_UNDEF':
                if e['addr'] == 0:
                    raise CLEInvalidBinaryError("Local symbol with address 0")
                name = e['name']
                loc[name] = e['addr']
        return loc



    @property
    def local_functions(self):
        dyna = self._local_functions(self.symbols)
        static= self._local_functions(self.s_symbols)
        return dict(dyna.items() + static.items())

    @property
    def local_symbols(self):
        dyna = self._local_symbols(self.symbols)
        static = self._local_symbols(self.s_symbols)
        return dict(dyna.items() + static.items())

    @property
    def global_symbols(self):
        dyna = self._global_symbols(self.symbols)
        static = self._global_symbols(self.s_symbols)
        return dict(dyna.items() + static.items())

    @property
    def global_functions(self):
        dyna = self._global_functions(self.symbols)
        static = self._global_functions(self.s_symbols)
        return dict(dyna.items() + static.items())



    @property
    def undef_symbols(self):
        undef = {}
        for e in self.symbols:
            if e['sh_info'] == 'SHN_UNDEF' and e['type'] == 'STT_OBJECT':
                name = e['name']
                undef[name] = e['addr']
                return undef

    @property
    def ifuncs(self):
        ifuncs={}
        for e in self.symbols:
            if e['type'] == 'STT_GNU_IFUNC':
                name = e['name']
                addr = e['addr']
                ifuncs[name] = addr
        return ifuncs

    def guess_function_name(self, addr):
        """
        Try to guess whether @addr is inside the code of a local function.
        Warning: is is approximate.
        """

        # The Elf class works with static non relocated addresses
        addr = addr - self.rebase_addr

        if not self.contains_addr(addr):
            return None

        local = self.local_functions
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

    def symbol(self, symbol):
        for si in self.symbols:
            if si["name"] == symbol:
                return si

    @property
    def gotaddr(self):
        """
        Notes:
        On x86, x86_64 DT_PLTGOT is equal to .got.plt, but different from .got
        On PPC, PPC64 DT_PLTGOT is equal to .plt, but different from .got
        """
        if self.arch.name in ('MIPS32', 'ARMEL', 'ARMHF'):
            # Dynamically-linked
            if self._dyn_gotaddr is not None: #DT_PLTGOT
                return self._dyn_gotaddr

        # Stripped binaries
        if len(self.sections) is None:
            return None

        if '.got' in self.sections:
            return self.sections['.got']['addr']


    @property
    def pltgotaddr(self):
        """
        Returns the addr of the jump (plt) section of the GOT, either from the
        dynamic section if there is any, or from the static sections otherwise.
        Same as .got on MIPS and ARM.
        On other architectures, this is a subset of the GOT referring to
        absolute addresses figuring in the PLT.
        """

        # On MIPS and ARM, DT_PLTGOT is equal to .got (and there is no .got.plt)
        if self.arch.name in ('MIPS32', 'ARMEL', 'ARMHF'):
            return self.gotaddr

        # Other arch, dynamically-linked
        if self._dyn_gotaddr is not None: #DT_PLTGOT
            return self._dyn_gotaddr

        # Stripped binaries
        if len(self.sections) is None:
            return None

        if self.arch.name in ('PPC32', 'PPC64'):
            if '.plt' in self.sections.keys():
                return self.sections['.plt']['addr']

        # Other arch
        if '.got.plt' in self.sections.keys():
            return self.sections['.got.plt']['addr']

    @property
    def gotsz(self):
        """
        TODO: infer that from dynamic info where possible
        """
        try:
            return self.sections['.got']['size']
        except KeyError:
            l.info("This binary seems to be stripped")
            return None

    @property
    def pltgotsz(self):
        if self.arch.name in ('MIPS32', 'ARMEL', 'ARMHF'):
            return self.gotsz

        if self.arch.name in ('PPC32', 'PPC64'):
            if '.plt' in self.sections.keys():
                return self.sections['.plt']['size']

        # Other arch
        if '.got.plt' in self.sections.keys():
            return self.sections['.got.plt']['size']

    def whatis(self, where):
        """
        Tells you what is at @addr
        """
        addr = None

        # Fist look in the GOT addresses of imports
        for name, addr in self.jmprel.iteritems():
            if where == addr:
                return name

        # Then in the local symbols
        for name, addr in self.local_functions.iteritems():
            if addr == where:
                return name

        for addr, name in self.local_symbols.iteritems():
            if addr == where:
                return name

        if self.linking == 'dynamic':
            # Look into global reloactions
            for name, addr in self.global_reloc.iteritems():
                if where == addr:
                    return name

        # Static symbol table
        for symb in self.s_symbols:
            if where == symb['addr']:
                return symb['name']

        string = self.strtab_value(where)
        if string is not None:
            return string


    def strtab_value(self, addr):
        """
        Is @addr corresponding to a strtab symbol ?
        """
        # Dynamic
        for off, val in self.strtab.iteritems():
            if off + self.strtab_vaddr == addr:
                return "String in strtab: %s " % repr(val)

    def _ppc64_abiv1_entry_fix(self):
        """
        On powerpc64, the e_flags elf header entry's lowest two bits determine
        the ABI type. in ABIv1, the entry point given in the elf headers is not
        actually the entry point, but rather the address in memory where there
        exists a pointer to the entry point.

        Utter bollocks, but this function should fix it.
        """

        self.ppc64_initial_rtoc = None
        if self.arch != 'PPC64': return
        if self.elfflags & 3 < 2:
            ep_offset = self._elf_entry
            self._elf_entry = self.memory.read_addr_at(ep_offset)
            self.ppc64_initial_rtoc = self.memory.read_addr_at(ep_offset+8)

