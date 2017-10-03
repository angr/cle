import struct
import subprocess
import logging
import archinfo
import elftools
from elftools.elf import elffile, sections
from elftools.common.exceptions import ELFError
from collections import OrderedDict, defaultdict

from .symbol import ELFSymbol, Symbol
from .regions import ELFSection, ELFSegment
from .hashtable import ELFHashTable, GNUHashTable
from .metaelf import MetaELF
from .. import register_backend
from .relocation import get_relocation
from .relocation.generic import MipsGlobalReloc, MipsLocalReloc
from ...patched_stream import PatchedStream
from ...errors import CLEError, CLEInvalidBinaryError, CLECompatibilityError
from ...utils import ALIGN_DOWN, ALIGN_UP, get_mmaped_data, stream_or_path
from ...address_translator import AT

l = logging.getLogger('cle.elf')

__all__ = ('ELFSymbol', 'ELF')


class ELF(MetaELF):
    """
    The main loader class for statically loading ELF executables. Uses the pyreadelf library where useful.
    """
    def __init__(self, binary, addend=None, **kwargs):
        super(ELF, self).__init__(binary, **kwargs)
        patch_undo = None
        try:
            self.reader = elffile.ELFFile(self.binary_stream)
        except ELFError:
            self.binary_stream.seek(4)
            ty = self.binary_stream.read(1)
            if ty not in ('\1', '\2'):
                raise CLECompatibilityError

            patch_data = (0x20, '\0\0\0\0') if ty == '\1' else (0x28, '\0\0\0\0\0\0\0\0')
            self.binary_stream.seek(patch_data[0])
            patch_undo = (patch_data[0], self.binary_stream.read(len(patch_data[1])))
            self.binary_stream = PatchedStream(self.binary_stream, [patch_data])
            l.error("PyReadELF couldn't load this file. Trying again without section headers...")

            try:
                self.reader = elffile.ELFFile(self.binary_stream)
            except ELFError:
                raise CLECompatibilityError

        # Get an appropriate archinfo.Arch for this binary, unless the user specified one
        if self.arch is None:
            self.set_arch(self.extract_arch(self.reader))

        self._addend = addend

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
        self._nullsymbol = Symbol(self, '', 0, 0, Symbol.TYPE_NONE)
        self._nullsymbol.is_static = True

        self._symbol_cache = {}
        self._symbols_by_name = {}
        self.demangled_names = {}
        self.imports = {}
        self.resolved_imports = []

        self.relocs = []
        self.jmprel = {}

        self._entry = self.reader.header.e_entry
        self.is_relocatable = self.reader.header.e_type == 'ET_REL'
        self.pic = self.reader.header.e_type in ('ET_REL', 'ET_DYN')

        self.tls_used = False
        self.tls_module_id = None
        self.tls_block_offset = None
        self.tls_block_size = None
        self.tls_tdata_start = None
        self.tls_tdata_size = None

        self.__parsed_reloc_tables = set()

        # The linked image base should be evaluated before registering any segment or section due to
        # the fact that elffile, used by those methods, is working only with un-based virtual addresses, but Clemories
        # themselves are organized as a tree where each node backer internally uses relative addressing
        seg_addrs = (ALIGN_DOWN(x['p_vaddr'], self.loader.page_size)
                     for x in self.reader.iter_segments() if x.header.p_type == 'PT_LOAD' and x.header.p_memsz > 0)
        self.mapped_base = self.linked_base = 0
        try:
            self.mapped_base = self.linked_base = min(seg_addrs)
        except ValueError:
            l.warn('no segments identified in PT_LOAD')

        self.__register_segments()
        self.__register_sections()

        # call the methods defined by MetaELF
        self._ppc64_abiv1_entry_fix()
        self._load_plt()

        self._populate_demangled_names()

        if patch_undo is not None:
            self.memory.write_bytes(AT.from_lva(self.min_addr + patch_undo[0], self).to_rva(), patch_undo[1])


    #
    # Properties and Public Methods
    #

    @classmethod
    def check_compatibility(cls, spec, obj):
        with stream_or_path(spec) as stream:
            return cls.extract_arch(elffile.ELFFile(stream)) == obj.arch

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith('\x7fELF'):
            if elftools.elf.elffile.ELFFile(stream).header['e_type'] == 'ET_CORE':
                return False
            return True
        return False

    @staticmethod
    def extract_arch(reader):
        arch_str = reader['e_machine']
        if arch_str == 'ARM':
            if reader.header.e_flags & 0x200:
                return archinfo.ArchARMEL('Iend_LE' if reader.little_endian else 'Iend_BE')
            elif reader.header.e_flags & 0x400:
                return archinfo.ArchARMHF('Iend_LE' if reader.little_endian else 'Iend_BE')
        else:
            return archinfo.arch_from_id(arch_str, 'le' if reader.little_endian else 'be', reader.elfclass)

    @property
    def initializers(self):
        if not self._inits_extracted: self._extract_init_fini()
        out = []
        if self.is_main_bin:
            # Preinitializers are ignored in shared objects.
            out.extend(self._preinit_arr)
        else:
            # The init func and the init array in the dynamic section are only run by the dynamic loader in shared objects.
            # In the main binary they are run by libc_csu_init.
            if self._init_func is not None:
                out.append(AT.from_lva(self._init_func, self).to_mva())
            out.extend(self._init_arr)
        return out

    @property
    def finalizers(self):
        if not self._inits_extracted: self._extract_init_fini()
        out = []
        if self._fini_func is not None:
            out.append(AT.from_lva(self._fini_func, self).to_mva())
        out.extend(map(lambda x: AT.from_lva(x, self).to_mva(), self._fini_arr))
        return out

    def get_symbol(self, symid, symbol_table=None): # pylint: disable=arguments-differ
        """
        Gets a Symbol object for the specified symbol.

        :param symid: Either an index into .dynsym or the name of a symbol.
        """
        if symbol_table is None:
            symbol_table = self.dynsym

        if isinstance(symid, (int, long)):
            if symid == 0:
                # special case the null symbol, this is important for static binaries
                return self._nullsymbol
            re_sym = symbol_table.get_symbol(symid)
            cache_key = self._symbol_to_tuple(re_sym)
            cached = self._symbol_cache.get(cache_key, None)
            if cached is not None:
                return cached
            symbol = ELFSymbol(self, re_sym)
            self._symbol_cache[cache_key] = symbol
            self._cache_symbol_name(symbol)
            return symbol
        elif isinstance(symid, (str,unicode)):
            if not symid:
                l.warn("Trying to resolve a symbol by its empty name")
                return None
            cached = self._symbols_by_name.get(symid, None)
            if cached:
                return cached
            if self.hashtable is None:
                return None
            re_sym = self.hashtable.get(symid)
            if re_sym is None:
                return None
            symbol = ELFSymbol(self, re_sym)
            self._symbol_cache[self._symbol_to_tuple(re_sym)] = symbol
            self._cache_symbol_name(symbol)
            return symbol
        elif isinstance(symid, sections.Symbol):
            cache_key = self._symbol_to_tuple(symid)
            cached = self._symbol_cache.get(cache_key, None)
            if cached is not None:
                return cached
            symbol = ELFSymbol(self, symid)
            self._symbol_cache[cache_key] = symbol
            self._cache_symbol_name(symbol)
            return symbol
        else:
            raise CLEError("Bad symbol identifier: %r" % (symid,))

    #
    # Private Methods
    #

    @staticmethod
    def _symbol_to_tuple(re_sym):
        """
        Returns a tuple of properties of the given PyELF symbol.
        This is unique enough as a key for both symbol lookup and retrieval.
        """
        entry = re_sym.entry
        return (entry.st_name, entry.st_value, entry.st_size, entry.st_info.bind,
                entry.st_info.type, entry.st_shndx)

    def _cache_symbol_name(self, symbol):
        name = symbol.name
        if name:
            if name in self._symbols_by_name:
                old_symbol = self._symbols_by_name[name]
                if not old_symbol.is_weak and symbol.is_weak:
                    return
            self._symbols_by_name[name] = symbol

    def _extract_init_fini(self):
        # Extract the initializers and finalizers
        if 'DT_PREINIT_ARRAY' in self._dynamic and 'DT_PREINIT_ARRAYSZ' in self._dynamic:
            arr_start = AT.from_lva(self._dynamic['DT_PREINIT_ARRAY'], self).to_rva()
            arr_end = arr_start + self._dynamic['DT_PREINIT_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._preinit_arr = map(self.memory.read_addr_at, range(arr_start, arr_end, arr_entsize))
        if 'DT_INIT' in self._dynamic:
            self._init_func = AT.from_lva(self._dynamic['DT_INIT'], self).to_rva()
        if 'DT_INIT_ARRAY' in self._dynamic and 'DT_INIT_ARRAYSZ' in self._dynamic:
            arr_start = AT.from_lva(self._dynamic['DT_INIT_ARRAY'], self).to_rva()
            arr_end = arr_start + self._dynamic['DT_INIT_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._init_arr = map(self.memory.read_addr_at, range(arr_start, arr_end, arr_entsize))
        if 'DT_FINI' in self._dynamic:
            self._fini_func = AT.from_lva(self._dynamic['DT_FINI'], self).to_rva()
        if 'DT_FINI_ARRAY' in self._dynamic and 'DT_FINI_ARRAYSZ' in self._dynamic:
            arr_start = AT.from_lva(self._dynamic['DT_FINI_ARRAY'], self).to_rva()
            arr_end = arr_start + self._dynamic['DT_FINI_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._fini_arr = map(self.memory.read_addr_at, range(arr_start, arr_end, arr_entsize))
        self._inits_extracted = True

    def _load_segment(self, seg):
        self._load_segment_metadata(seg)
        self._load_segment_memory(seg)

    def _load_segment_metadata(self, seg):
        """
        Loads a segment based on a LOAD directive in the program header table.
        """
        loaded_segment = ELFSegment(seg)
        self.segments.append(loaded_segment)

    def _load_segment_memory(self, seg):

        # see https://code.woboq.org/userspace/glibc/elf/dl-load.c.html#1066
        ph = seg.header

        if ph.p_align & (self.loader.page_size - 1) != 0:
            l.error("ELF file %s is loading a segment which is not page-aligned... do you need to change the page size?", self.binary)

        if (ph.p_vaddr - ph.p_offset) & (ph.p_align - 1) != 0:
            raise CLEInvalidBinaryError("ELF file %s is loading a segment with an inappropriate alignment" % self.binary)
        if ph.p_filesz > ph.p_memsz:
            raise CLEInvalidBinaryError("ELF file %s is loading a segment with an inappropriate allocation" % self.binary)

        mapstart = ALIGN_DOWN(ph.p_vaddr, self.loader.page_size)
        mapend = ALIGN_UP(ph.p_vaddr + ph.p_filesz, self.loader.page_size)

        dataend = ph.p_vaddr + ph.p_filesz
        allocend = ph.p_vaddr + ph.p_memsz

        mapoff = ALIGN_DOWN(ph.p_offset, self.loader.page_size)

        # see https://code.woboq.org/userspace/glibc/elf/dl-map-segments.h.html#88
        data = get_mmaped_data(seg.stream, mapoff, mapend - mapstart, self.loader.page_size)

        if allocend > dataend:
            zero = dataend
            zeropage = (zero + self.loader.page_size - 1) & ~(self.loader.page_size - 1)

            if zeropage > zero:
                data = data[:zero - mapstart].ljust(zeropage - mapstart, '\0')

            zeroend = ALIGN_UP(allocend, self.loader.page_size) # mmap maps to the next page boundary
            if zeroend > zeropage:
                data = data.ljust(zeroend - mapstart, '\0')

        self.memory.add_backer(AT.from_lva(mapstart, self).to_rva(), data)

    def _make_reloc(self, readelf_reloc, symbol, dest_section=None):
        addend = readelf_reloc.entry.r_addend if readelf_reloc.is_RELA() else None
        RelocClass = get_relocation(self.arch.name, readelf_reloc.entry.r_info_type)
        if RelocClass is None:
            return None

        address = AT.from_lva(readelf_reloc.entry.r_offset, self).to_rva()
        if dest_section is not None:
            address += dest_section.remap_offset

        return RelocClass(self, symbol, address, addend)

    def _populate_demangled_names(self):
        """
        TODO: remove this once a python implementation of a name demangler has
        been implemented, then update self.demangled_names in Symbol
        """

        if not self._symbols_by_addr:
            return

        names = filter(lambda n: n.startswith("_Z"), (s.name for s in self._symbols_by_addr.itervalues()))
        lookup_names = map(lambda n: n.split("@@")[0], names)
        # this monstrosity taken from stackoverflow
        # http://stackoverflow.com/questions/6526500/c-name-mangling-library-for-python
        args = ['c++filt']
        args.extend(lookup_names)
        try:
            pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            demangled = stdout.split("\n")[:-1]

            self.demangled_names = dict(zip(names, demangled))
        except OSError:
            pass

    #
    # Private Methods... really. Calling these out of context
    # will probably break things. Caveat emptor.
    #

    def __getstate__(self):
        if self.binary is None:
            raise ValueError("Can't pickle an object loaded from a stream")

        # Cache the objects before trashing them so we can continue
        # working without re-loading the pickle
        rdr = self.reader
        strt = self.strtab
        dyn = self.dynsym
        hsh = self.hashtable
        bs = self.binary_stream

        # Trash the unpickleable
        if type(self.binary_stream) is PatchedStream:
            self.binary_stream.stream = None
        else:
            self.binary_stream = None

        self.reader = None
        self.strtab = None
        self.dynsym = None
        self.hashtable = None

        # Get a copy of our pickleable self
        out = dict(self.__dict__)

        # Restore the cached items
        self.reader = rdr
        self.strtab = strt
        self.dynsym = dyn
        self.hashtable = hsh
        self.binary_stream = bs

        return out

    def __setstate__(self, data):
        self.__dict__.update(data)
        if self.binary_stream is None:
            self.binary_stream = open(self.binary, 'rb')
        else:
            self.binary_stream.stream = open(self.binary, 'rb')
        self.reader = elffile.ELFFile(self.binary_stream)
        if self._dynamic and 'DT_STRTAB' in self._dynamic:
            fakestrtabheader = {
                'sh_offset': AT.from_lva(self._dynamic['DT_STRTAB'], self).to_rva()
            }
            self.strtab = elffile.StringTableSection(fakestrtabheader, 'strtab_cle', self.memory)
            if 'DT_SYMTAB' in self._dynamic and 'DT_SYMENT' in self._dynamic:
                fakesymtabheader = {
                    'sh_offset': AT.from_lva(self._dynamic['DT_SYMTAB'], self).to_rva(),
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0
                } # bogus size: no iteration allowed
                self.dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.memory, self.reader, self.strtab)
                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(self.dynsym, self.memory,
                                                  AT.from_lva(self._dynamic['DT_GNU_HASH'], self).to_rva(), self.arch)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(self.dynsym, self.memory,
                                                  AT.from_lva(self._dynamic['DT_HASH'], self).to_rva(), self.arch)

    def __register_segments(self):
        self.linking = 'static'
        if self.is_relocatable and self.reader.num_segments() > 0:
            # WTF?
            raise CLEError("Relocatable objects with segments are not supported.")

        type_to_seg_mapping = defaultdict(list)
        for seg_readelf in self.reader.iter_segments():
            type_to_seg_mapping[seg_readelf.header.p_type].append(seg_readelf)

        # PT_LOAD segments must be processed first so that the memory_backers for the other segments exist
        for seg in type_to_seg_mapping['PT_LOAD']:
            self._load_segment(seg)

        # the order of processing for the other three handled segment_types should not matter, but let's have it consistent
        for seg in type_to_seg_mapping['PT_DYNAMIC']:
            self.__register_dyn(seg)
            self.linking = 'dynamic'

        for seg in type_to_seg_mapping['PT_TLS']:
            self.__register_tls(seg)

        for seg in type_to_seg_mapping['PT_GNU_STACK']:
            self.execstack = bool(seg.header.p_flags & 1)

    def __register_dyn(self, seg_readelf):
        """
        Parse the dynamic section for dynamically linked objects.
        """
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
                'sh_offset': AT.from_lva(self._dynamic['DT_STRTAB'], self).to_rva()
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
                    'sh_offset': AT.from_lva(self._dynamic['DT_SYMTAB'], self).to_rva(),
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0
                } # bogus size: no iteration allowed
                self.dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.memory, self.reader, self.strtab)

                # set up the hash table, prefering the gnu hash section to the old hash section
                # the hash table lets you get any symbol given its name
                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(
                        self.dynsym, self.memory, AT.from_lva(self._dynamic['DT_GNU_HASH'], self).to_rva(), self.arch)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(
                        self.dynsym, self.memory, AT.from_lva(self._dynamic['DT_HASH'], self).to_rva(), self.arch)
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
                    reloffset = self._dynamic['DT_' + self.rela_type] and \
                                AT.from_lva(self._dynamic['DT_' + self.rela_type], self).to_rva()
                    if 'DT_' + self.rela_type + 'SZ' not in self._dynamic:
                        raise CLEInvalidBinaryError('Dynamic section contains DT_' + self.rela_type +
                                ', but DT_' + self.rela_type + 'SZ is not present')
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
                    jmpreloffset = self._dynamic['DT_JMPREL'] and AT.from_lva(self._dynamic['DT_JMPREL'], self).to_rva()
                    if 'DT_PLTRELSZ' not in self._dynamic:
                        raise CLEInvalidBinaryError('Dynamic section contains DT_JMPREL, but DT_PLTRELSZ is not present')
                    jmprelsz = self._dynamic['DT_PLTRELSZ']
                    fakejmprelheader = {
                        'sh_offset': jmpreloffset,
                        'sh_type': 'SHT_' + self.rela_type,
                        'sh_entsize': relentsz,
                        'sh_size': jmprelsz
                    }
                    readelf_jmprelsec = elffile.RelocationSection(fakejmprelheader, 'jmprel_cle', self.memory, self.reader)
                    self.jmprel = OrderedDict((reloc.symbol.name, reloc) for reloc in self.__register_relocs(readelf_jmprelsec) if reloc.symbol.name != '')

    def __register_relocs(self, section):
        if section.header['sh_offset'] in self.__parsed_reloc_tables:
            return
        self.__parsed_reloc_tables.add(section.header['sh_offset'])

        # Get the target section's remapping offset for relocations
        dest_sec = None
        dest_sec_idx = section.header.get('sh_info', None)
        if dest_sec_idx is not None:
            try:
                dest_sec = self.sections[dest_sec_idx]
            except IndexError:
                l.warn('the relocation section %s refers to unknown section index: %d', section.name, dest_sec_idx)
            else:
                if not dest_sec.occupies_memory:
                    # The target section is not loaded into memory, so just continue
                    return

        symtab = self.reader.get_section(section.header['sh_link']) if 'sh_link' in section.header else None
        relocs = []
        for readelf_reloc in section.iter_relocations():
            # MIPS64 is just plain old fucked up
            # https://www.sourceware.org/ml/libc-alpha/2003-03/msg00153.html
            if self.arch.name == 'MIPS64':
                # Little endian additionally needs one of its fields reversed... WHY
                if self.arch.memory_endness == 'Iend_LE':
                    readelf_reloc.entry.r_info_sym = readelf_reloc.entry.r_info & 0xFFFFFFFF
                    readelf_reloc.entry.r_info = struct.unpack('>Q', struct.pack('<Q', readelf_reloc.entry.r_info))[0]

                type_1 = readelf_reloc.entry.r_info & 0xFF
                type_2 = readelf_reloc.entry.r_info >> 8 & 0xFF
                type_3 = readelf_reloc.entry.r_info >> 16 & 0xFF
                extra_sym = readelf_reloc.entry.r_info >> 24 & 0xFF
                if extra_sym != 0:
                    l.error('r_info_extra_sym is nonzero??? PLEASE SEND HELP')
                symbol = self.get_symbol(readelf_reloc.entry.r_info_sym, symtab)

                if type_1 != 0:
                    readelf_reloc.entry.r_info_type = type_1
                    reloc = self._make_reloc(readelf_reloc, symbol, dest_sec)
                    if reloc is not None:
                        relocs.append(reloc)
                        self.relocs.append(reloc)
                if type_2 != 0:
                    readelf_reloc.entry.r_info_type = type_2
                    reloc = self._make_reloc(readelf_reloc, symbol, dest_sec)
                    if reloc is not None:
                        relocs.append(reloc)
                        self.relocs.append(reloc)
                if type_3 != 0:
                    readelf_reloc.entry.r_info_type = type_3
                    reloc = self._make_reloc(readelf_reloc, symbol, dest_sec)
                    if reloc is not None:
                        relocs.append(reloc)
                        self.relocs.append(reloc)
            else:
                symbol = self.get_symbol(readelf_reloc.entry.r_info_sym, symtab)
                reloc = self._make_reloc(readelf_reloc, symbol, dest_sec)
                if reloc is not None:
                    relocs.append(reloc)
                    self.relocs.append(reloc)
        return relocs

    def __register_tls(self, seg_readelf):
        self.tls_used = True
        self.tls_block_size = seg_readelf.header.p_memsz
        self.tls_tdata_size = seg_readelf.header.p_filesz
        self.tls_tdata_start = seg_readelf.header.p_vaddr

    def __register_sections(self):
        new_addr = 0
        sec_list = []

        for sec_readelf in self.reader.iter_sections():
            remap_offset = 0
            if self.is_relocatable and sec_readelf.header['sh_flags'] & 2:      # alloc flag
                # Relocatable objects' section addresses are meaningless (they are meant to be relocated anyway)
                # We thus have to map them manually to valid virtual addresses to emulate a linker's behaviour.
                sh_addr = sec_readelf.header['sh_addr']
                align = sec_readelf.header['sh_addralign']
                if align > 0:
                    new_addr = (new_addr + (align - 1)) // align * align

                remap_offset = new_addr - sh_addr
                new_addr += sec_readelf.header['sh_size']    # address for next section

            section = ELFSection(sec_readelf, remap_offset=remap_offset)
            sec_list.append((sec_readelf, section))

            # Register sections first, process later - this is required by relocatable objects
            self.sections.append(section)
            self.sections_map[section.name] = section

        for sec_readelf, section in sec_list:
            if isinstance(sec_readelf, elffile.SymbolTableSection):
                self.__register_section_symbols(sec_readelf)
            if isinstance(sec_readelf, elffile.RelocationSection) and not \
                    ('DT_REL' in self._dynamic or 'DT_RELA' in self._dynamic or 'DT_JMPREL' in self._dynamic):
                self.__register_relocs(sec_readelf)

            if section.occupies_memory:      # alloc flag - stick in memory maybe!
                if AT.from_lva(section.vaddr, self).to_rva() not in self.memory:        # only allocate if not already allocated (i.e. by program header)
                    if section.type == 'SHT_NOBITS':
                        self.memory.add_backer(AT.from_lva(section.vaddr, self).to_rva(), '\0'*sec_readelf.header['sh_size'])
                    else: #elif section.type == 'SHT_PROGBITS':
                        self.memory.add_backer(AT.from_lva(section.vaddr, self).to_rva(), sec_readelf.data())

    def __register_section_symbols(self, sec_re):
        for sym_re in sec_re.iter_symbols():
            self.get_symbol(sym_re)

    def __relocate_mips(self):
        if 'DT_MIPS_BASE_ADDRESS' not in self._dynamic:
            return False
        # The MIPS GOT is an array of addresses, simple as that.
        got_local_num = self._dynamic['DT_MIPS_LOCAL_GOTNO'] # number of local GOT entries
        # a.k.a the index of the first global GOT entry
        symtab_got_idx = self._dynamic['DT_MIPS_GOTSYM']   # index of first symbol w/ GOT entry
        symbol_count = self._dynamic['DT_MIPS_SYMTABNO']
        gotaddr = AT.from_lva(self._dynamic['DT_PLTGOT'], self).to_rva()
        wordsize = self.arch.bytes
        for i in range(2, got_local_num):
            reloc = MipsLocalReloc(self, None, gotaddr + i*wordsize)
            self.relocs.append(reloc)

        for i in range(symbol_count - symtab_got_idx):
            symbol = self.get_symbol(i + symtab_got_idx)
            reloc = MipsGlobalReloc(self, symbol, gotaddr + (i + got_local_num)*wordsize)
            self.relocs.append(reloc)
            self.jmprel[symbol.name] = reloc
        return True

register_backend('elf', ELF)
