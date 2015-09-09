import struct
from elftools.elf import elffile, sections
import archinfo

from .absobj import Symbol, Relocation, Segment, Section
from .metaelf import MetaELF
from .errors import CLEError, CLEInvalidBinaryError

import logging
l = logging.getLogger('cle.elf')

__all__ = ('ELFSymbol', 'ELF')

class ELFSymbol(Symbol):
    def __init__(self, owner, symb):
        realtype = owner.arch.translate_symbol_type(symb.entry.st_info.type)
        super(ELFSymbol, self).__init__(owner,
                                        symb.name,
                                        symb.entry.st_value,
                                        symb.entry.st_size,
                                        symb.entry.st_info.bind,
                                        realtype,
                                        symb.entry.st_shndx)

class ELFRelocation(Relocation):
    def __init__(self, readelf_reloc, owner, symbol):
        addend = readelf_reloc.entry.r_addend if readelf_reloc.is_RELA() else None
        super(ELFRelocation, self).__init__(owner,
                                            symbol,
                                            readelf_reloc.entry.r_offset,
                                            readelf_reloc.entry.r_info_type,
                                            addend)

class ELFSegment(Segment):
    def __init__(self, readelf_seg):
        self.flags = readelf_seg.header.p_flags
        super(ELFSegment, self).__init__(readelf_seg.header.p_offset,
                                         readelf_seg.header.p_vaddr,
                                         readelf_seg.header.p_filesz,
                                         readelf_seg.header.p_memsz)

    @property
    def is_readable(self):
        return self.flags & 4 != 0

    @property
    def is_writable(self):
        return self.flags & 2 != 0

    @property
    def is_executable(self):
        return self.flags & 1 != 0

class ELFSection(Section):
    def __init__(self, readelf_sec):
        super(ELFSection, self).__init__(readelf_sec.name,
                                         readelf_sec.header.sh_offset,
                                         readelf_sec.header.sh_addr,
                                         readelf_sec.header.sh_size,
                                         readelf_sec.header.sh_type,
                                         readelf_sec.header.sh_entsize,
                                         readelf_sec.header.sh_flags,
                                         readelf_sec.header.sh_link,
                                         readelf_sec.header.sh_info,
                                         readelf_sec.header.sh_addralign)

class ELF(MetaELF):
    '''
     The main loader class for statically loading elves. Uses the pyreadelf library where useful.
    '''
    def __init__(self, binary, **kwargs):
        super(ELF, self).__init__(binary, **kwargs)
        self.reader = elffile.ELFFile(open(self.binary, 'rb'))

        # Get an appropriate archinfo.Arch for this binary, unless the user specified one
        if self.arch is None:
            if self.reader.header.e_machine == 'EM_ARM' and \
                    self.reader.header.e_flags & 0x200:
                self.set_arch(archinfo.ArchARMEL('Iend_LE' if 'LSB' in self.reader.header.e_ident.EI_DATA else 'Iend_BE'))
            elif self.reader.header.e_machine == 'EM_ARM' and \
                    self.reader.header.e_flags & 0x400:
                self.set_arch(archinfo.ArchARMHF('Iend_LE' if 'LSB' in self.reader.header.e_ident.EI_DATA else 'Iend_BE'))
            else:
                self.set_arch(archinfo.arch_from_id(self.reader.header.e_machine,
                                                self.reader.header.e_ident.EI_DATA,
                                                self.reader.header.e_ident.EI_CLASS))

        self.strtab = None
        self.dynsym = None
        self.hashtable = None

        self._dynamic = {}
        self.deps = []
        self.rela_type = None

        self._inits_extracted = False
        self._preinit_arr = []
        self._init_func = None
        self._init_arr = []
        self._fini_func = None
        self._fini_arr = []

        self._symbol_cache = {}
        self.symbols_by_addr = {}
        self.imports = {}
        self.resolved_imports = []

        self.relocs = []
        self.jmprel = {}

        self._entry = self.reader.header.e_entry
        self.pic = self.reader.header.e_type == 'ET_DYN'

        self.tls_used = False
        self.tls_module_id = None
        self.tls_block_offset = None
        self.tls_block_size = None
        self.tls_tdata_start = None
        self.tls_tdata_size = None

        self.__register_segments()
        self.__register_sections()

        # call the methods defined by MetaELF
        self._ppc64_abiv1_entry_fix()
        self._load_plt()

    def __getstate__(self):
        self.reader = None
        self.strtab = None
        self.dynsym = None
        self.hashtable = None
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)
        self.reader = elffile.ELFFile(open(self.binary, 'rb'))
        if self._dynamic and 'DT_STRTAB' in self._dynamic:
            fakestrtabheader = {
                'sh_offset': self._dynamic['DT_STRTAB']
            }
            self.strtab = elffile.StringTableSection(fakestrtabheader, 'strtab_cle', self.memory)
            if 'DT_SYMTAB' in self._dynamic and 'DT_SYMENT' in self._dynamic:
                fakesymtabheader = {
                    'sh_offset': self._dynamic['DT_SYMTAB'],
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0
                } # bogus size: no iteration allowed
                self.dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.memory, self.reader, self.strtab)
                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(self.dynsym, self.memory, self._dynamic['DT_GNU_HASH'], self.arch)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(self.dynsym, self.memory, self._dynamic['DT_HASH'], self.arch)

    def get_symbol(self, symid):
        """
        Gets a Symbol object for the specified symbol

        @param symid: either an index into .dynsym or the name of a symbol.
        """
        if isinstance(symid, (int, long)):
            re_sym = self.dynsym.get_symbol(symid)
            if re_sym.name in self._symbol_cache:
                return self._symbol_cache[re_sym.name]
            symbol = ELFSymbol(self, re_sym)
            self._symbol_cache[re_sym.name] = symbol
            return symbol
        elif isinstance(symid, str):
            if symid in self._symbol_cache:
                return self._symbol_cache[symid]
            if self.hashtable is None:
                return None
            re_sym = self.hashtable.get(symid)
            if re_sym is None:
                return None
            symbol = ELFSymbol(self, re_sym)
            self._symbol_cache[symid] = symbol
            return symbol
        elif isinstance(symid, sections.Symbol):
            if symid.name in self._symbol_cache:
                return self._symbol_cache[symid.name]
            symbol = ELFSymbol(self, symid)
            self._symbol_cache[symid.name] = symbol
            return symbol
        else:
            raise CLEError("Bad symbol identifier: %s" % symid)

    def _extract_init_fini(self):
        # Extract the initializers and finalizers
        if 'DT_PREINIT_ARRAY' in self._dynamic and 'DT_PREINIT_ARRAYSZ' in self._dynamic:
            arr_start = self._dynamic['DT_PREINIT_ARRAY']
            arr_end = arr_start + self._dynamic['DT_PREINIT_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._preinit_arr = map(self.memory.read_addr_at, range(arr_start, arr_end, arr_entsize))
        if 'DT_INIT' in self._dynamic:
            self._init_func = self._dynamic['DT_INIT']
        if 'DT_INIT_ARRAY' in self._dynamic and 'DT_INIT_ARRAYSZ' in self._dynamic:
            arr_start = self._dynamic['DT_INIT_ARRAY']
            arr_end = arr_start + self._dynamic['DT_INIT_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._init_arr = map(self.memory.read_addr_at, range(arr_start, arr_end, arr_entsize))
        if 'DT_FINI' in self._dynamic:
            self._fini_func = self._dynamic['DT_FINI']
        if 'DT_FINI_ARRAY' in self._dynamic and 'DT_FINI_ARRAYSZ' in self._dynamic:
            arr_start = self._dynamic['DT_FINI_ARRAY']
            arr_end = arr_start + self._dynamic['DT_FINI_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._fini_arr = map(self.memory.read_addr_at, range(arr_start, arr_end, arr_entsize))
        self._inits_extracted = True


    def get_initializers(self):
        if not self._inits_extracted: self._extract_init_fini()
        out = []
        if self.is_main_bin:
            # Preinitializers are ignored in shared objects.
            out.extend(self._preinit_arr)
        else:
            # The init func and the init array in the dynamic section are only run by the dynamic loader in shared objects.
            # In the main binary they are run by libc_csu_init.
            if self._init_func is not None:
                out.append(self._init_func + self.rebase_addr)
            out.extend(self._init_arr)
        return out

    def get_finalizers(self):
        if not self._inits_extracted: self._extract_init_fini()
        out = []
        if self._fini_func is not None:
            out.append(self._fini_func + self.rebase_addr)
        out.extend(map(self._rebase_addr, self._fini_arr))
        return out

    def __register_segments(self):
        for seg_readelf in self.reader.iter_segments():
            if seg_readelf.header.p_type == 'PT_LOAD':
                self._load_segment(seg_readelf)
            elif seg_readelf.header.p_type == 'PT_DYNAMIC':
                self.__register_dyn(seg_readelf)
            elif seg_readelf.header.p_type == 'PT_TLS':
                self.__register_tls(seg_readelf)
            elif seg_readelf.header.p_type == 'PT_GNU_STACK':
                self.execstack = bool(seg_readelf.header.p_flags & 1)

    def _rebase_addr(self, addr):
        return addr + self.rebase_addr

    def _load_segment(self, seg):
        '''
         Loads a segment based on a LOAD directive in the program header table
        '''
        self.segments.append(ELFSegment(seg))
        seg_data = seg.data()
        if seg.header.p_memsz > seg.header.p_filesz:
            seg_data += '\0' * (seg.header.p_memsz - seg.header.p_filesz)
        self.memory.add_backer(seg.header.p_vaddr, seg_data)

    def __register_dyn(self, seg_readelf):
        '''
         Parse the dynamic section for dynamically linked objects
        '''
        for tag in seg_readelf.iter_tags():
            # Create a dictionary, self._dynamic, mapping DT_* strings to their values
            tagstr = self.arch.translate_dynamic_tag(tag.entry.d_tag)
            self._dynamic[tagstr] = tag.entry.d_val
            # For tags that may appear more than once, handle them here
            if tagstr == 'DT_NEEDED':
                self.deps.append(tag.entry.d_val)

        # None of the following things make sense without a string table
        if 'DT_STRTAB' in self._dynamic:
            # To handle binaries without section headers, we need to hack around pyreadelf's assumptions
            # make our own string table
            fakestrtabheader = {
                'sh_offset': self._dynamic['DT_STRTAB']
            }
            self.strtab = elffile.StringTableSection(fakestrtabheader, 'strtab_cle', self.memory)

            # get the list of strings that are the required shared libraries
            self.deps = map(self.strtab.get_string, self.deps)

            # get the string for the "shared object name" that this binary provides
            if 'DT_SONAME' in self._dynamic:
                self.provides = self.strtab.get_string(self._dynamic['DT_SONAME'])

            # None of the following structures can be used without a symbol table
            if 'DT_SYMTAB' in self._dynamic and 'DT_SYMENT' in self._dynamic:
                # Construct our own symbol table to hack around pyreadelf assuming section headers are around
                fakesymtabheader = {
                    'sh_offset': self._dynamic['DT_SYMTAB'],
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0
                } # bogus size: no iteration allowed
                self.dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.memory, self.reader, self.strtab)

                # set up the hash table, prefering the gnu hash section to the old hash section
                # the hash table lets you get any symbol given its name
                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(self.dynsym, self.memory, self._dynamic['DT_GNU_HASH'], self.arch)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(self.dynsym, self.memory, self._dynamic['DT_HASH'], self.arch)
                else:
                    l.warning("No hash table available in %s", self.binary)

                # mips' relocations are absolutely screwed up, handle some of them here.
                self.__relocate_mips()

                # perform a lot of checks to figure out what kind of relocation tables are around
                self.rela_type = None
                if 'DT_PLTREL' in self._dynamic:
                    if self._dynamic['DT_PLTREL'] == 7:
                        self.rela_type = 'RELA'
                        relentsz = self.reader.structs.Elf_Rela.sizeof()
                    elif self._dynamic['DT_PLTREL'] == 17:
                        self.rela_type = 'REL'
                        relentsz = self.reader.structs.Elf_Rel.sizeof()
                    else:
                        raise CLEInvalidBinaryError('DT_PLTREL is not REL or RELA?')
                else:
                    if 'DT_RELA' in self._dynamic:
                        self.rela_type = 'RELA'
                        relentsz = self.reader.structs.Elf_Rela.sizeof()
                    elif 'DT_REL' in self._dynamic:
                        self.rela_type = 'REL'
                        relentsz = self.reader.structs.Elf_Rel.sizeof()
                    else:
                        return

                # try to parse relocations out of a table of type DT_REL{,A}
                if 'DT_' + self.rela_type in self._dynamic:
                    reloffset = self._dynamic['DT_' + self.rela_type]
                    relsz = self._dynamic['DT_' + self.rela_type + 'SZ']
                    fakerelheader = {
                        'sh_offset': reloffset,
                        'sh_type': 'SHT_' + self.rela_type,
                        'sh_entsize': relentsz,
                        'sh_size': relsz
                    }
                    readelf_relocsec = elffile.RelocationSection(fakerelheader, 'reloc_cle', self.memory, self.reader)
                    self.__register_relocs(readelf_relocsec)

                # try to parse relocations out of a table of type DT_JMPREL
                if 'DT_JMPREL' in self._dynamic:
                    jmpreloffset = self._dynamic['DT_JMPREL']
                    jmprelsz = self._dynamic['DT_PLTRELSZ']
                    fakejmprelheader = {
                        'sh_offset': jmpreloffset,
                        'sh_type': 'SHT_' + self.rela_type,
                        'sh_entsize': relentsz,
                        'sh_size': jmprelsz
                    }
                    readelf_jmprelsec = elffile.RelocationSection(fakejmprelheader, 'jmprel_cle', self.memory, self.reader)
                    self.jmprel = {reloc.symbol.name: reloc for reloc in self.__register_relocs(readelf_jmprelsec)}

    def __register_relocs(self, section):
        relocs = []
        for readelf_reloc in section.iter_relocations():
            # MIPS64 is just plain old fucked up
            # https://www.sourceware.org/ml/libc-alpha/2003-03/msg00153.html
            if self.arch.name == 'MIPS64':
                # Little endian addionally needs one of its fields reversed... WHY
                if self.arch.memory_endness == 'Iend_LE':
                    readelf_reloc.entry.r_info_sym = readelf_reloc.entry.r_info & 0xFFFFFFFF
                    readelf_reloc.entry.r_info = struct.unpack('>Q', struct.pack('<Q', readelf_reloc.entry.r_info))[0]

                type_1 = readelf_reloc.entry.r_info & 0xFF
                type_2 = readelf_reloc.entry.r_info >> 8 & 0xFF
                type_3 = readelf_reloc.entry.r_info >> 16 & 0xFF
                extra_sym = readelf_reloc.entry.r_info >> 24 & 0xFF
                if extra_sym != 0:
                    l.error('r_info_extra_sym is nonzero??? PLEASE SEND HELP')
                symbol = self.get_symbol(readelf_reloc.entry.r_info_sym)

                if type_1 != 0:
                    readelf_reloc.entry.r_info_type = type_1
                    reloc = ELFRelocation(readelf_reloc, self, symbol)
                    relocs.append(reloc)
                    self.relocs.append(reloc)
                if type_2 != 0:
                    readelf_reloc.entry.r_info_type = type_2
                    reloc = ELFRelocation(readelf_reloc, self, symbol)
                    relocs.append(reloc)
                    self.relocs.append(reloc)
                if type_3 != 0:
                    readelf_reloc.entry.r_info_type = type_3
                    reloc = ELFRelocation(readelf_reloc, self, symbol)
                    relocs.append(reloc)
                    self.relocs.append(reloc)
            else:
                symbol = self.get_symbol(readelf_reloc.entry.r_info_sym)
                reloc = ELFRelocation(readelf_reloc, self, symbol)
                relocs.append(reloc)
                self.relocs.append(reloc)
        return relocs


    def __register_tls(self, seg_readelf):
        self.tls_used = True
        self.tls_block_size = seg_readelf.header.p_memsz
        self.tls_tdata_size = seg_readelf.header.p_filesz
        self.tls_tdata_start = seg_readelf.header.p_vaddr

    def __register_sections(self):
        for sec_readelf in self.reader.iter_sections():
            section = ELFSection(sec_readelf)
            self.sections.append(section)
            self.sections_map[section.name] = section
            if isinstance(sec_readelf, elffile.SymbolTableSection):
                self.__register_section_symbols(sec_readelf)

    def __register_section_symbols(self, sec_re):
        for sym_re in sec_re.iter_symbols():
            if sym_re.name == '':
                continue
            self.get_symbol(sym_re)

    def __relocate_mips(self):
        if 'DT_MIPS_BASE_ADDRESS' not in self._dynamic:
            return False
        got_local_num = self._dynamic['DT_MIPS_LOCAL_GOTNO'] # number of local GOT entries
        # a.k.a the index of the first global GOT entry
        symtab_got_idx = self._dynamic['DT_MIPS_GOTSYM']   # index of first symbol w/ GOT entry
        symbol_count = self._dynamic['DT_MIPS_SYMTABNO']
        gotaddr = self._dynamic['DT_PLTGOT']
        wordsize = self.arch.bytes
        for i in range(got_local_num):
            reloc = Relocation(self, None, gotaddr + i*wordsize, 'mips_local')
            self.relocs.append(reloc)

        for i in range(symbol_count - symtab_got_idx):
            symbol = self.get_symbol(i + symtab_got_idx)
            reloc = Relocation(self, symbol, gotaddr + (i + got_local_num)*wordsize, 'mips_global')
            self.relocs.append(reloc)
            self.jmprel[symbol.name] = reloc
        return True

class ELFHashTable(object):
    """
    Functions to do lookup from a HASH section of an ELF file.

    Information: http://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html
    """
    def __init__(self, symtab, stream, offset, arch):
        """
        @param symtab       The symbol table to perform lookups from (as a pyelftools SymbolTableSection)
        @param stream       A file-like object to read from the ELF's memory
        @param offset       The offset in the object where the table starts
        @param arch         The ArchInfo object for the ELF file
        """
        self.symtab = symtab
        fmt = '<' if arch.memory_endness == 'Iend_LE' else '>'
        stream.seek(offset)
        self.nbuckets, self.nchains = struct.unpack(fmt + 'II', stream.read(8))
        self.buckets = struct.unpack(fmt + 'I'*self.nbuckets, stream.read(4*self.nbuckets))
        self.chains = struct.unpack(fmt + 'I'*self.nchains, stream.read(4*self.nchains))

    def get(self, k):
        """
        Perform a lookup. Returns a pyelftools Symbol object, or None if there is no match.

        @param k        The string to look up
        """
        hval = self.elf_hash(k) % self.nbuckets
        symndx = self.buckets[hval]
        while symndx != 0:
            sym = self.symtab.get_symbol(symndx)
            if sym.name == k:
                return sym
            symndx = self.chains[symndx]
        return None

    # from http://www.partow.net/programming/hashfunctions/
    @staticmethod
    def elf_hash(key):
        h = 0
        x = 0
        for i in range(len(key)):
            h = (h << 4) + ord(key[i])
            x = h & 0xF0000000
            if x != 0:
                h ^= (x >> 24)
            h &= ~x
        return h

class GNUHashTable(object):
    """
    Functions to do lookup from a GNU_HASH section of an ELF file.

    Information: https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
    """
    def __init__(self, symtab, stream, offset, arch):
        """
        @param symtab       The symbol table to perform lookups from (as a pyelftools SymbolTableSection)
        @param stream       A file-like object to read from the ELF's memory
        @param offset       The offset in the object where the table starts
        @param arch         The ArchInfo object for the ELF file
        """
        self.symtab = symtab
        fmt = '<' if arch.memory_endness == 'Iend_LE' else '>'
        self.c = arch.bits
        fmtsz = 'I' if self.c == 32 else 'Q'

        stream.seek(offset)
        self.nbuckets, self.symndx, self.maskwords, self.shift2 = \
                struct.unpack(fmt + 'IIII', stream.read(16))

        self.bloom = struct.unpack(fmt + fmtsz*self.maskwords, stream.read(self.c*self.maskwords/8))
        self.buckets = struct.unpack(fmt + 'I'*self.nbuckets, stream.read(4*self.nbuckets))

    def _matches_bloom(self, H1):
        C = self.c
        H2 = H1 >> self.shift2
        N = ((H1 / C) & (self.maskwords - 1))
        BITMASK = (1 << (H1 % C)) | (1 << (H2 % C))
        return (self.bloom[N] & BITMASK) == BITMASK

    def get(self, k):
        """
        Perform a lookup. Returns a pyelftools Symbol object, or None if there is no match.

        @param k        The string to look up
        """
        h = self.gnu_hash(k)
        if not self._matches_bloom(h):
            return None
        n = self.buckets[h % self.nbuckets]
        if n == 0:
            return None
        try:
            sym = self.symtab.get_symbol(n)
            while True:
                if sym.name == k:
                    return sym
                n += 1
                sym = self.symtab.get_symbol(n)
                if (self.gnu_hash(sym.name) % self.nbuckets) != (h % self.nbuckets):
                    break
        except KeyError:
            pass
        return None

    @staticmethod
    def gnu_hash(key):
        h = 5381
        for c in key:
            h = h * 33 + ord(c)
        return h & 0xFFFFFFFF
