import struct
import readelf
from elftools.elf import sections, relocation

from .abs_obj import AbsObj, Symbol, Relocation, Segment
from .clexception import CLException

import logging
l = logging.getLogger('cle.elf')

class ELFSymbol(Symbol):
    def __init__(self, owner, symb):
        super(ELFSymbol, self).__init__(owner, symb.name, symb.entry.st_value,
                                        symb.entry.st_size, symb.entry.st_info.bind,
                                        symb.entry.st_info.type, symb.entry.st_shndx)

class ELFRelocation(Relocation):
    def __init__(self, readelf_reloc, owner, symbol):
        addend = readelf_reloc.entry.r_addend if readelf_reloc.is_RELA() else None
        super(ELFRelocation, self).__init__(owner, symbol, readelf_reloc.entry.r_offset,
                                            readelf_reloc.entry.r_info_type, addend)

class ELFSegment(Segment):
    def __init__(self, readelf_seg):
        super(ELFSegment, self).__init__('seg_%x' % readelf_seg.header.p_vaddr, readelf_seg.header.p_vaddr, readelf_seg.header.p_memsz, readelf_seg.header.p_filesz, readelf_seg.header.p_offset)

class Elf(AbsObj):
    def __init__(self, binary, **kwargs):
        super(Elf, self).__init__(binary, **kwargs)
        self.reader = readelf.ELFFile(open(self.binary))

        self.strtab = None
        self.dynsym = None
        self.hashtable = None
        self._symbol_cache = {}
        self.deps = []
        self.soname = None
        self.rela_type = None
        self.resolved_imports = []
        self.imports = {}

        self._dynamic = {}

        self.relocs = []
        self.copy_reloc = []
        self.global_reloc = []
        self.s_a_reloc = []
        self.relative_reloc = []
        self.jmprel = {}

        self.tls_mod_reloc = {}
        self.tls_offset_reloc = {}

        self.elfflags = self.reader.header.e_flags
        self.entry = self.reader.header.e_entry
        self.archinfo.elfflags = self.elfflags

        self.__register_segments()

    def __register_segments(self):
        for seg_readelf in self.reader.iter_segments():
            if seg_readelf.header.p_type == 'PT_LOAD':
                self._load_segment(seg_readelf)
            elif seg_readelf.header.p_type == 'PT_DYNAMIC':
                self.__register_dyn(seg_readelf)

    def _load_segment(self, seg):
        self.memory.add_backer(seg.header.p_vaddr, seg.data())
        self.segments.append(ELFSegment(seg))
        if seg.header.p_memsz > seg.header.p_filesz:
            self.memory.add_backer(seg.header.p_vaddr + seg.header.p_filesz, '\0' * (seg.header.p_memsz - seg.header.p_filesz))

    def __register_dyn(self, seg_readelf):
        #import ipdb; ipdb.set_trace()
        for tag in seg_readelf.iter_tags():
            self._dynamic[tag.entry.d_tag] = tag.entry.d_val
            if tag.entry.d_tag == 'DT_NEEDED':
                self.deps.append(tag.entry.d_val)
        if 'DT_STRTAB' in self._dynamic:
            fakestrtabheader = {
                'sh_offset': self._dynamic['DT_STRTAB']
            }
            self.strtab = sections.StringTableSection(fakestrtabheader, 'strtab_cle', self.memory)
            self.deps = map(self.strtab.get_string, self.deps)
            if 'DT_SONAME' in self._dynamic:
                self.soname = self.strtab.get_string(self._dynamic['DT_SONAME'])
            if 'DT_SYMTAB' in self._dynamic and 'DT_SYMENT' in self._dynamic:
                fakesymtabheader = {
                    'sh_offset': self._dynamic['DT_SYMTAB'],
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0
                } # bogus size: no iteration allowed
                self.dynsym = sections.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.memory, self.reader, self.strtab)

                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(self.dynsym, self.memory, self._dynamic['DT_GNU_HASH'], self.archinfo)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(self.dynsym, self.memory, self._dynamic['DT_HASH'], self.archinfo)
                else:
                    l.warning("No hash table available in %s", self.binary)

                if self._dynamic['DT_PLTREL'] == 7:
                    self.rela_type = 'RELA'
                elif self._dynamic['DT_PLTREL'] == 17:
                    self.rela_type = 'REL'
                else:
                    raise CLException('DT_PLTREL is not REL or RELA?')

                reloffset = self._dynamic['DT_' + self.rela_type]
                relentsz = self._dynamic['DT_' + self.rela_type + 'ENT']
                relsz = self._dynamic['DT_' + self.rela_type + 'SZ']
                fakerelheader = {
                    'sh_offset': reloffset,
                    'sh_type': 'SHT_' + self.rela_type,
                    'sh_entsize': relentsz,
                    'sh_size': relsz
                }
                readelf_relocsec = relocation.RelocationSection(fakerelheader, 'reloc_cle', self.memory, self.reader)
                self.__register_relocs(readelf_relocsec)

                if 'DT_JMPREL' in self._dynamic:
                    jmpreloffset = self._dynamic['DT_JMPREL']
                    jmprelsz = self._dynamic['DT_PLTRELSZ']
                    fakejmprelheader = {
                        'sh_offset': jmpreloffset,
                        'sh_type': 'SHT_' + self.rela_type,
                        'sh_entsize': relentsz,
                        'sh_size': jmprelsz
                    }
                    readelf_jmprelsec = relocation.RelocationSection(fakejmprelheader, 'jmprel_cle', self.memory, self.reader)
                    self.jmprel = {reloc.symbol.name: reloc for reloc in self.__register_relocs(readelf_jmprelsec)}

    def __register_relocs(self, section):
        relocs = []
        for readelf_reloc in section.iter_relocations():
            symbol = self.get_symbol(readelf_reloc.entry.r_info_sym)
            reloc = ELFRelocation(readelf_reloc, self, symbol)
            relocs.append(reloc)
            self.relocs.append(reloc)
            if reloc.type in self.archinfo.get_global_reloc_type():
                self.global_reloc.append(reloc)
            elif reloc.type in self.archinfo.get_s_a_reloc_type():
                self.s_a_reloc.append(reloc)
            elif reloc.type in self.archinfo.get_relative_reloc_type():
                self.relative_reloc.append(reloc)
            elif reloc.type in self.archinfo.get_copy_reloc_type():
                self.copy_reloc.append(reloc)
            else:
                l.warning("Unknown reloc type: %d", reloc.type)
        return relocs


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
        else:
            raise CLException("Bad symbol identifier: %s" % symid)

class ELFHashTable(object):
    def __init__(self, symtab, stream, offset, archinfo):
        self.symtab = symtab
        fmt = '<' if archinfo.byte_order == 'LSB' else '>'
        stream.seek(offset)
        self.nbuckets, self.nchains = struct.unpack(fmt + 'II', stream.read(8))
        self.buckets = struct.unpack(fmt + 'I'*self.nbuckets, stream.read(4*self.nbuckets))
        self.chains = struct.unpack(fmt + 'I'*self.nchains, stream.read(4*self.nchains))

    def get(self, k):
        hval = self.elf_hash(k) % self.nbuckets
        while hval != 0:
            bval = self.buckets[hval]
            sym = self.symtab.get_symbol(bval)
            if sym.name == k:
                return sym
            hval = self.chains[bval]
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
    def __init__(self, symtab, stream, offset, archinfo):
        self.symtab = symtab
        fmt = '<' if archinfo.byte_order == 'LSB' else '>'
        self.c = archinfo.bits
        fmtsz = 'I' if self.c == 32 else 'Q'

        stream.seek(offset)
        self.nbuckets, self.symndx, self.maskwords, self.shift2 = \
                struct.unpack(fmt + 'IIII', stream.read(16))

        self.bloom = struct.unpack(fmt + fmtsz*self.maskwords, stream.read(self.c*self.maskwords/8))
        self.buckets = struct.unpack(fmt + 'I'*self.nbuckets, stream.read(4*self.nbuckets))

    def matches_bloom(self, H1):
        C = self.c
        H2 = H1 >> self.shift2
        N = ((H1 / C) & (self.maskwords - 1))
        BITMASK = (1 << (H1 % C)) | (1 << (H2 % C))
        return (self.bloom[N] & BITMASK) == BITMASK

    def get(self, k):
        h = self.gnu_hash(k)
        if not self.matches_bloom(h):
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
