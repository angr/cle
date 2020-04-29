import copy
import os
import logging
import archinfo
import elftools
from elftools.elf import elffile, sections
from elftools.dwarf import callframe
from elftools.common.exceptions import ELFError, DWARFError
from collections import OrderedDict, defaultdict

from .symbol import ELFSymbol, Symbol, SymbolType
from .regions import ELFSection, ELFSegment
from .hashtable import ELFHashTable, GNUHashTable
from .metaelf import MetaELF, maybedecode
from .lsda import LSDAExceptionTable
from .. import register_backend, FunctionHint, FunctionHintSource, ExceptionHandling
from .relocation import get_relocation
from .relocation.generic import MipsGlobalReloc, MipsLocalReloc
from ...patched_stream import PatchedStream
from ...errors import CLEError, CLEInvalidBinaryError, CLECompatibilityError
from ...utils import ALIGN_DOWN, ALIGN_UP, get_mmaped_data, stream_or_path
from ...address_translator import AT

l = logging.getLogger(name=__name__)

__all__ = ('ELFSymbol', 'ELF')


class ELF(MetaELF):
    """
    The main loader class for statically loading ELF executables. Uses the pyreadelf library where useful.
    """
    is_default = True  # Tell CLE to automatically consider using the ELF backend

    def __init__(self, *args, addend=None, debug_symbols=None, **kwargs):
        super().__init__(*args, **kwargs)
        patch_undo = []
        try:
            self._reader = elffile.ELFFile(self._binary_stream)
            list(self._reader.iter_sections())
        except Exception: # pylint: disable=broad-except
            self._binary_stream.seek(4)
            ty = self._binary_stream.read(1)
            if ty not in (b'\1', b'\2'):
                raise CLECompatibilityError

            if ty == b'\1':
                patch_data = [(0x20, b'\0'*4), (0x2e, b'\0'*6)]
            else:
                patch_data = [(0x28, b'\0'*8), (0x3a, b'\0'*6)]

            for offset, patch in patch_data:
                self._binary_stream.seek(offset)
                patch_undo.append((offset, self._binary_stream.read(len(patch))))

            self._binary_stream = PatchedStream(self._binary_stream, patch_data)
            l.error("PyReadELF couldn't load this file. Trying again without section headers...")

            try:
                self._reader = elffile.ELFFile(self._binary_stream)
            except Exception as e: # pylint: disable=broad-except
                raise CLECompatibilityError from e

        # Get an appropriate archinfo.Arch for this binary, unless the user specified one
        if self.arch is None:
            self.set_arch(self.extract_arch(self._reader))
        else:
            other_arch = self.extract_arch(self._reader)
            if other_arch != self.arch:
                l.warning("User specified %s but autodetected %s. Proceed with caution.", self.arch, other_arch)

        self._addend = addend

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
        self._nullsymbol = Symbol(self, '', 0, 0, SymbolType.TYPE_NONE)
        self._nullsymbol.is_static = True

        self._symbol_cache = {}
        self._symbols_by_name = {}
        self._desperate_for_symbols = False
        self.imports = {}
        self.resolved_imports = []
        self.tls_block_offset = None  # this is an ELF-only attribute

        self.relocs = []
        self.jmprel = OrderedDict()

        #
        # DWARF data
        #
        self.has_dwarf_info = bool(self._reader.has_dwarf_info())
        self.build_id = None

        self._entry = self._reader.header.e_entry
        self.is_relocatable = self._reader.header.e_type == 'ET_REL'
        self.pic = self.pic or self._reader.header.e_type in ('ET_REL', 'ET_DYN')

        self.__parsed_reloc_tables = set()

        # The linked image base should be evaluated before registering any segment or section due to
        # the fact that elffile, used by those methods, is working only with un-based virtual addresses, but Clemories
        # themselves are organized as a tree where each node backer internally uses relative addressing
        seg_addrs = (ALIGN_DOWN(x['p_vaddr'], self.loader.page_size)
                     for x in self._reader.iter_segments() if x.header.p_type == 'PT_LOAD' and x.header.p_memsz > 0)
        self.mapped_base = self.linked_base = 0
        try:
            self.mapped_base = self.linked_base = min(seg_addrs)
        except ValueError:
            l.info('no PT_LOAD segments identified')

        self.__register_segments()
        self.__register_sections()

        if not self.symbols:
            self._desperate_for_symbols = True
            self.symbols.update(self._symbol_cache.values())

        if self.has_dwarf_info and self.loader._load_debug_info:
            # load DWARF information
            try:
                dwarf = self._reader.get_dwarf_info()
            except ELFError:
                l.warning("An exception occurred in pyelftools when loading the DWARF information for %s. "
                          "Marking DWARF as not available for this binary.", self.binary_basename, exc_info=True)
                dwarf = None
                self.has_dwarf_info = False

            if dwarf and dwarf.has_EH_CFI():
                self._load_function_hints_from_fde(dwarf, FunctionHintSource.EH_FRAME)
                self._load_exception_handling(dwarf)

        if debug_symbols:
            self.__process_debug_file(debug_symbols)
        elif self.loader._load_debug_info and self.build_id:
            debug_filename = '/usr/lib/debug/.build-id/%s/%s.debug' % (self.build_id[:2], self.build_id[2:])
            if os.path.isfile(debug_filename):
                self.__process_debug_file(debug_filename)

        # call the methods defined by MetaELF
        self._ppc64_abiv1_entry_fix()
        self._load_plt()

        for offset, patch in patch_undo:
            self.memory.store(AT.from_lva(self.min_addr + offset, self).to_rva(), patch)


    #
    # Properties and Public Methods
    #

    def close(self):
        super().close()
        del self._reader

    @classmethod
    def check_compatibility(cls, spec, obj):
        with stream_or_path(spec) as stream:
            try:
                return cls.extract_arch(elffile.ELFFile(stream)) == obj.arch
            except archinfo.ArchNotFound:
                return False

    @classmethod
    def check_magic_compatibility(cls, stream):
        stream.seek(0)
        identstring = stream.read(0x10)
        stream.seek(0)
        return identstring.startswith(b'\x7fELF')

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith(b'\x7fELF'):
            if elftools.elf.elffile.ELFFile(stream).header['e_type'] == 'ET_CORE':
                return False
            return True
        return False

    @staticmethod
    def _extract_arm_attrs(reader):
        # EDG says: Did you know ARM puts a whole special section in their elves to hold all their ABI junk?
        # As ARM architectures start to diverge a bunch, we actually need this data to pick out
        # what to do.  Particularly for us, it's whether we're doing Cortex-M or not, as our other ARM support
        # is generic

        # TODO: There's a whole pile of useful stuff in here. We should use it some day.
        attrs_sec = reader.get_section_by_name('.ARM.attributes')
        if not attrs_sec:
            return None  # No attrs here!
        attrs_sub_sec = None
        for subsec in attrs_sec.subsections:
            if isinstance(subsec, elftools.elf.sections.ARMAttributesSubsection):
                attrs_sub_sec = subsec
                break
        if not attrs_sub_sec:
            return None  # None here either
        attrs_sub_sub_sec = None
        for subsubsec in attrs_sub_sec.subsubsections:
            if isinstance(subsubsec, elftools.elf.sections.ARMAttributesSubsubsection):
                attrs_sub_sub_sec = subsubsec
                break
        if not attrs_sub_sub_sec:
            return None  # None here either
        # Ok, now we can finally look at the goods
        atts = {}
        for attobj in attrs_sub_sub_sec.attributes:
            atts[attobj.tag] = attobj.value
        return atts

    @staticmethod
    def extract_arch(reader):
        arch_str = reader['e_machine']
        if 'ARM' in arch_str:
            # Check the ARM attributes, if they exist
            arm_attrs = ELF._extract_arm_attrs(reader)
            if arm_attrs and 'TAG_CPU_NAME' in arm_attrs:
                if arm_attrs['TAG_CPU_NAME'].endswith("-M") \
                    or 'Cortex-M' in arm_attrs['TAG_CPU_NAME']:
                    return archinfo.ArchARMCortexM('Iend_LE')
            if reader.header.e_flags & 0x200:
                return archinfo.ArchARMEL('Iend_LE' if reader.little_endian else 'Iend_BE')
            elif reader.header.e_flags & 0x400:
                return archinfo.ArchARMHF('Iend_LE' if reader.little_endian else 'Iend_BE')

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

    @property
    def symbols_by_name(self):
        return self._symbols_by_name.copy()

    def get_symbol(self, symid, symbol_table=None): # pylint: disable=arguments-differ
        """
        Gets a Symbol object for the specified symbol.

        :param symid: Either an index into .dynsym or the name of a symbol.
        """
        if type(symid) is int:
            if symid == 0:
                # special case the null symbol, this is important for static binaries
                return self._nullsymbol
            if symbol_table is None:
                raise TypeError("Must specify the symbol table to look up symbols by index")
            try:
                re_sym = symbol_table.get_symbol(symid)
            except Exception:  # pylint: disable=broad-except
                l.exception("Error parsing symbol at %#08x", symid)
                return None
            cache_key = self._symbol_to_tuple(re_sym)
            cached = self._symbol_cache.get(cache_key, None)
            if cached is not None:
                return cached
            symbol = ELFSymbol(self, re_sym)
            self._symbol_cache[cache_key] = symbol
            self._cache_symbol_name(symbol)
            return symbol
        elif type(symid) is str:
            if not symid:
                l.warning("Trying to resolve a symbol by its empty name")
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
            if self._desperate_for_symbols:
                idx = self.symbols.bisect_key_left(symbol.relative_addr)
                if idx >= len(self.symbols) or self.symbols[idx].name != name:
                    self.symbols.add(symbol)

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
            self._preinit_arr = list(map(self.memory.unpack_word, range(arr_start, arr_end, arr_entsize)))
        if 'DT_INIT' in self._dynamic:
            self._init_func = AT.from_lva(self._dynamic['DT_INIT'], self).to_rva()
        if 'DT_INIT_ARRAY' in self._dynamic and 'DT_INIT_ARRAYSZ' in self._dynamic:
            arr_start = AT.from_lva(self._dynamic['DT_INIT_ARRAY'], self).to_rva()
            arr_end = arr_start + self._dynamic['DT_INIT_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._init_arr = list(map(self.memory.unpack_word, range(arr_start, arr_end, arr_entsize)))
        if 'DT_FINI' in self._dynamic:
            self._fini_func = AT.from_lva(self._dynamic['DT_FINI'], self).to_rva()
        if 'DT_FINI_ARRAY' in self._dynamic and 'DT_FINI_ARRAYSZ' in self._dynamic:
            arr_start = AT.from_lva(self._dynamic['DT_FINI_ARRAY'], self).to_rva()
            arr_end = arr_start + self._dynamic['DT_FINI_ARRAYSZ']
            arr_entsize = self.arch.bytes
            self._fini_arr = list(map(self.memory.unpack_word, range(arr_start, arr_end, arr_entsize)))
        self._inits_extracted = True

    def _load_segment(self, seg):
        loaded_segment = ELFSegment(seg)
        self.segments.append(loaded_segment)

        # see https://code.woboq.org/userspace/glibc/elf/dl-load.c.html#1066
        ph = seg.header

        if ph.p_align & (self.loader.page_size - 1) != 0:
            l.error("ELF file %s is loading a segment which is not page-aligned... do you need to change the page size?", self.binary)

        if (ph.p_vaddr - ph.p_offset) & (ph.p_align - 1) != 0:
            l.warning("ELF file %s is loading a segment with an inappropriate alignment. It might not work in all contexts.", self.binary)
        if ph.p_filesz > ph.p_memsz:
            raise CLEInvalidBinaryError("ELF file %s is loading a segment with an inappropriate allocation" % self.binary)

        mapstart = ALIGN_DOWN(ph.p_vaddr, self.loader.page_size)
        mapend = ALIGN_UP(ph.p_vaddr + ph.p_filesz, self.loader.page_size)

        dataend = ph.p_vaddr + ph.p_filesz
        allocend = ph.p_vaddr + ph.p_memsz

        mapoff = ALIGN_DOWN(ph.p_offset, self.loader.page_size)

        # patch modified addresses into ELFSegment
        loaded_segment.vaddr = mapstart
        loaded_segment.memsize = mapend - mapstart
        loaded_segment.filesize = mapend - mapstart
        loaded_segment.offset = mapoff

        # see https://code.woboq.org/userspace/glibc/elf/dl-map-segments.h.html#88
        data = get_mmaped_data(seg.stream, mapoff, mapend - mapstart, self.loader.page_size)
        if allocend > dataend:
            zero = dataend
            zeropage = (zero + self.loader.page_size - 1) & ~(self.loader.page_size - 1)

            if zeropage > zero:
                data = data[:zero - mapstart].ljust(zeropage - mapstart, b'\0')

            zeroend = ALIGN_UP(allocend, self.loader.page_size) # mmap maps to the next page boundary
            if zeroend > zeropage:
                data = data.ljust(zeroend - mapstart, b'\0')
            loaded_segment.memsize = zeroend - mapstart
        elif not data:
            l.warning("Segment %s is empty at %#08x!", seg.header.p_type, mapstart)
            return

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

    def _load_function_hints_from_fde(self, dwarf, source):
        """
        Load frame description entries out of the .eh_frame section. These entries include function addresses and can be
        used to improve CFG recovery.

        :param dwarf:   The DWARF info object from pyelftools.
        :return:        None
        """

        try:
            for entry in dwarf.EH_CFI_entries():
                if type(entry) is callframe.FDE:
                    self.function_hints.append(FunctionHint(
                        entry.header['initial_location'],
                        entry.header['address_range'],
                        source,
                    ))
        except (DWARFError, ValueError):
            l.warning("An exception occurred in pyelftools when loading FDE information.",
                      exc_info=True)

    def _load_exception_handling(self, dwarf):
        """
        Load exception handling information out of the .eh_frame and .gcc_except_table sections. We may support more
        types of exception handling information in the future.

        :param dwarf:   The DWARF info object from pyelftools.
        :return:        None
        """

        try:
            lsda = LSDAExceptionTable(self._binary_stream, self.arch.bits, self.arch.memory_endness == 'Iend_LE')
            for entry in dwarf.EH_CFI_entries():
                if type(entry) is callframe.FDE and \
                        hasattr(entry, 'lsda_pointer') and \
                        entry.lsda_pointer is not None:
                    # function address
                    func_addr = entry.header.get('initial_location', None)
                    if func_addr is None:
                        l.warning('Unexpected FDE structure: '
                                  'initial_location is not specified while LSDA pointer is available.')
                        continue

                    # Load and parse LSDA exception table
                    file_offset = self.addr_to_offset(entry.lsda_pointer)
                    lsda_exception_table = lsda.parse_lsda(entry.lsda_pointer, file_offset)
                    for exc in lsda_exception_table:
                        handling = ExceptionHandling(
                            func_addr + exc.cs_start,
                            exc.cs_len,
                            handler_addr=func_addr + exc.cs_lp if exc.cs_lp != 0 else None,
                            func_addr=func_addr
                        )
                        self.exception_handlings.append(handling)

        except (DWARFError, ValueError):
            l.warning("An exception occurred in pyelftools when loading FDE information.",
                      exc_info=True)

    #
    # Private Methods... really. Calling these out of context
    # will probably break things. Caveat emptor.
    #

    def __register_segments(self):
        self.linking = 'static'
        if self.is_relocatable and self._reader.num_segments() > 0:
            # WTF?
            raise CLEError("Relocatable objects with segments are not supported.")

        type_to_seg_mapping = defaultdict(list)
        for seg_readelf in self._reader.iter_segments():
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

        for seg in type_to_seg_mapping['PT_GNU_RELRO']:
            self.__register_relro(seg)

    def __register_dyn(self, seg_readelf):
        """
        Parse the dynamic section for dynamically linked objects.
        """
        runpath, rpath = "", ""
        for tag in seg_readelf.iter_tags():
            # Create a dictionary, self._dynamic, mapping DT_* strings to their values
            tagstr = self.arch.translate_dynamic_tag(tag.entry.d_tag)
            self._dynamic[tagstr] = tag.entry.d_val
            # For tags that may appear more than once, handle them here
            if tagstr == 'DT_NEEDED':
                self.deps.append(maybedecode(tag.needed))
            elif tagstr == 'DT_SONAME':
                self.provides = maybedecode(tag.soname)
            elif tagstr == 'DT_RUNPATH':
                runpath = maybedecode(tag.runpath)
            elif tagstr == 'DT_RPATH':
                rpath = maybedecode(tag.rpath)

        self.extra_load_path = self.__parse_rpath(runpath, rpath)

        strtab = seg_readelf._get_stringtable()
        self.__neuter_streams(strtab)

        # To extract symbols from binaries without section headers, we need to hack into pyelftools.
        # TODO: pyelftools is less bad than it used to be. how much of this can go away?
        # None of the following things make sense without a string table or a symbol table
        if 'DT_STRTAB' in self._dynamic and 'DT_SYMTAB' in self._dynamic and 'DT_SYMENT' in self._dynamic:
                # Construct our own symbol table to hack around pyreadelf assuming section headers are around
                fakesymtabheader = {
                    'sh_offset': AT.from_lva(self._dynamic['DT_SYMTAB'], self).to_rva(),
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0, # bogus size: no iteration allowed
                    'sh_flags': 0,
                    'sh_addralign': 0,
                }
                dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self._reader, strtab)
                dynsym.stream = self.memory
                dynsym.elffile = None

                # set up the hash table, preferring the gnu hash section to the old hash section
                # the hash table lets you get any symbol given its name
                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(
                        dynsym, self.memory, AT.from_lva(self._dynamic['DT_GNU_HASH'], self).to_rva(), self.arch)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(
                        dynsym, self.memory, AT.from_lva(self._dynamic['DT_HASH'], self).to_rva(), self.arch)
                else:
                    l.warning("No hash table available in %s", self.binary)

                # mips' relocations are absolutely screwed up, handle some of them here.
                self.__relocate_mips(dynsym)

                # perform a lot of checks to figure out what kind of relocation tables are around
                self.rela_type = None
                if 'DT_PLTREL' in self._dynamic:
                    if self._dynamic['DT_PLTREL'] == 7:
                        self.rela_type = 'RELA'
                        relentsz = self._reader.structs.Elf_Rela.sizeof()
                    elif self._dynamic['DT_PLTREL'] == 17:
                        self.rela_type = 'REL'
                        relentsz = self._reader.structs.Elf_Rel.sizeof()
                    else:
                        raise CLEInvalidBinaryError('DT_PLTREL is not REL or RELA?')
                else:
                    if 'DT_RELA' in self._dynamic:
                        self.rela_type = 'RELA'
                        relentsz = self._reader.structs.Elf_Rela.sizeof()
                    elif 'DT_REL' in self._dynamic:
                        self.rela_type = 'REL'
                        relentsz = self._reader.structs.Elf_Rel.sizeof()
                    else:
                        return

                # try to parse relocations out of a table of type DT_REL{,A}
                rela_tag = 'DT_' + self.rela_type
                relsz_tag = rela_tag + 'SZ'
                if rela_tag in self._dynamic:
                    reloffset = AT.from_lva(self._dynamic[rela_tag], self).to_rva()
                    if relsz_tag not in self._dynamic:
                        raise CLEInvalidBinaryError('Dynamic section contains %s but not %s' % (rela_tag, relsz_tag))
                    relsz = self._dynamic[relsz_tag]
                    fakerelheader = {
                        'sh_offset': reloffset,
                        'sh_type': 'SHT_' + self.rela_type,
                        'sh_entsize': relentsz,
                        'sh_size': relsz,
                        'sh_flags': 0,
                        'sh_addralign': 0,
                    }
                    readelf_relocsec = elffile.RelocationSection(fakerelheader, 'reloc_cle', self._reader)
                    readelf_relocsec.stream = self.memory
                    readelf_relocsec.elffile = None
                    self.__register_relocs(readelf_relocsec, dynsym)

                # try to parse relocations out of a table of type DT_JMPREL
                if 'DT_JMPREL' in self._dynamic:
                    jmpreloffset = AT.from_lva(self._dynamic['DT_JMPREL'], self).to_rva()
                    if 'DT_PLTRELSZ' not in self._dynamic:
                        raise CLEInvalidBinaryError('Dynamic section contains DT_JMPREL but not DT_PLTRELSZ')
                    jmprelsz = self._dynamic['DT_PLTRELSZ']
                    fakejmprelheader = {
                        'sh_offset': jmpreloffset,
                        'sh_type': 'SHT_' + self.rela_type,
                        'sh_entsize': relentsz,
                        'sh_size': jmprelsz,
                        'sh_flags': 0,
                        'sh_addralign': 0,
                    }
                    readelf_jmprelsec = elffile.RelocationSection(fakejmprelheader, 'jmprel_cle', self._reader)
                    readelf_jmprelsec.stream = self.memory
                    readelf_jmprelsec.elffile = None
                    self.__register_relocs(readelf_jmprelsec, dynsym, force_jmprel=True)

    def __parse_rpath(self, runpath, rpath):
        """
        Split RPATH/RUNPATH tags into a list of paths while expanding rpath tokens.
        """
        # DT_RUNPATH takes predence over DT_RPATH
        if len(runpath) > 0:
            pass
        else:
            runpath = rpath

        parts = []
        for part in runpath.split(":"):
            # does not handle $LIB/$PLATFORM substitutions yet
            if self.binary is not None:
                part = part.replace('$ORIGIN', os.path.dirname(self.binary))
            elif '$ORIGIN' in part:
                l.warning("DT_RUNPATH/DT_RPATH of the binary contains $ORIGIN tokens but no self.binary, some libraries might be not found")
            parts.append(part)
        return parts

    def __register_relocs(self, section, dynsym=None, force_jmprel=False):
        if not self.loader._perform_relocations:
            return

        got_min = got_max = 0

        if not force_jmprel:
            got_sec = self._reader.get_section_by_name('.got')
            if got_sec is not None:
                got_min = got_sec.header.sh_addr
                got_max = got_min + got_sec.header.sh_size

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
                l.warning('the relocation section %s refers to unknown section index: %d', section.name, dest_sec_idx)
            else:
                if dest_sec.is_active and not dest_sec.occupies_memory:
                    # The target section is not loaded into memory, so just continue
                    return

        symtab = self._reader.get_section(section.header['sh_link']) if 'sh_link' in section.header else dynsym
        if isinstance(symtab, elftools.elf.sections.NullSection):
            # Oh my god Atmel please stop
            symtab = self._reader.get_section_by_name('.symtab')
        relocs = []
        for readelf_reloc in section.iter_relocations():
            # MIPS64 is just plain old fucked up
            # https://www.sourceware.org/ml/libc-alpha/2003-03/msg00153.html
            if self.arch.name == 'MIPS64':
                type_1 = readelf_reloc.entry.r_info_type
                type_2 = readelf_reloc.entry.r_info_type2
                type_3 = readelf_reloc.entry.r_info_type3
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
                if symbol is None:
                    continue
                reloc = self._make_reloc(readelf_reloc, symbol, dest_sec)
                if reloc is not None:
                    relocs.append(reloc)
                    self.relocs.append(reloc)

        for reloc in relocs:
            if reloc.symbol.name != '' and (force_jmprel or got_min <= reloc.linked_addr < got_max):
                self.jmprel[reloc.symbol.name] = reloc

    def __register_tls(self, seg_readelf):
        self.tls_used = True
        self.tls_block_size = seg_readelf.header.p_memsz
        self.tls_data_size = seg_readelf.header.p_filesz
        self.tls_data_start = AT.from_lva(seg_readelf.header.p_vaddr, self).to_rva()

    def __register_relro(self, segment_relro):
        segment_relro = ELFSegment(segment_relro, relro=True)
        vaddr = ALIGN_DOWN(segment_relro.vaddr, self.loader.page_size)
        vaddr_end = ALIGN_UP(vaddr + segment_relro.memsize, self.loader.page_size)
        vaddr_endfile = ALIGN_UP(vaddr + segment_relro.filesize, self.loader.page_size)

        segment_relro.offset = ALIGN_DOWN(segment_relro.offset, self.loader.page_size)
        segment_relro.vaddr = vaddr
        segment_relro.memsize = vaddr_end - vaddr
        segment_relro.filesize = vaddr_endfile - vaddr

        def ___segments_overlap(seg1, seg2):
            # Re-arrange so seg1 starts first
            seg1, seg2 = (seg1, seg2) if seg1.min_addr < seg2.min_addr else (seg2, seg1)
            # seg1 and seg2 overlap if seg2 starts before seg1 ends
            return seg2.min_addr <= seg1.max_addr

        overlapping_segments = [seg for seg in self.segments if ___segments_overlap(segment_relro, seg)]

        if len(overlapping_segments) == 0:
            l.error("RELRO segment does not overlap with any loaded segment.")
            return

        if len(overlapping_segments) > 1:
            # I don't think this ever happens.  If it does, weshould
            # probably also split the RELRO segment so that each one
            # has the right permissions in case the two overlapping
            # segments have different permissions.
            l.warning("RELRO segment overlaps multiple segments.")

        for overlapping_segment in overlapping_segments:
            # We will split the overlapping segment into two pieces:
            # one for the segment below the RELRO segment, and one for
            # above.
            segment_below = copy.copy(overlapping_segment)
            segment_below.memsize = segment_relro.min_addr - overlapping_segment.min_addr
            segment_below.filesize = max(segment_below.filesize, segment_below.memsize)

            segment_above = copy.copy(overlapping_segment)
            segment_above.vaddr = segment_relro.max_addr + 1
            segment_above.memsize = overlapping_segment.max_addr - segment_above.vaddr + 1
            segment_above.filesize = max(0, segment_above.filesize - segment_relro.memsize - segment_below.memsize)
            segment_above.offset = segment_above.offset + segment_below.memsize + segment_relro.memsize

            split_segments = [segment_below, segment_relro, segment_above]
            split_segments = [seg for seg in split_segments if seg.memsize > 0]

            # Remove the original segment
            self.segments.remove(overlapping_segment)

            # Add the new ones
            for seg in split_segments:
                self.segments.append(seg)

        # Add the actual relro segment, and mark it as always
        # read-only.  We use the flags of the overlapping original
        # segment.
        segment_relro.flags = overlapping_segments[0].flags & ~2

    def __register_sections(self):
        new_addr = 0
        sec_list = []

        for sec_readelf in self._reader.iter_sections():
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
                self.__register_relocs(sec_readelf, dynsym=None)

            if section.occupies_memory:      # alloc flag - stick in memory maybe!
                if AT.from_lva(section.vaddr, self).to_rva() not in self.memory:        # only allocate if not already allocated (i.e. by program header)
                    if section.type == 'SHT_NOBITS':
                        self.memory.add_backer(AT.from_lva(section.vaddr, self).to_rva(), b'\0'*sec_readelf.header['sh_size'])
                    else: #elif section.type == 'SHT_PROGBITS':
                        self.memory.add_backer(AT.from_lva(section.vaddr, self).to_rva(), sec_readelf.data())

            if sec_readelf.header.sh_type == 'SHT_NOTE':
                self.__register_notes(sec_readelf)

            if section.name == '.comment':
                self.__analyze_comments(sec_readelf.data())

    def __register_notes(self, sec_readelf):
        for note in sec_readelf.iter_notes():
            if note.n_type == 'NT_GNU_BUILD_ID' and note.n_name == 'GNU':
                if self.build_id is not None and self.build_id != note.n_desc:
                    l.error("Mismatched build IDs present")
                self.build_id = note.n_desc

    def __analyze_comments(self, data):
        try:
            data = data.decode().split('\0')
        except UnicodeDecodeError:
            return

        for line in data:
            versions = [word for word in line.replace('(', ' ').replace(')', ' ').split() if '.' in word]
            if not versions:
                continue
            versions.sort(key=len)
            version = versions[-1]
            lline = line.lower()
            if 'clang' in lline:
                compiler = 'clang'
            elif 'gcc' in lline:
                compiler = 'gcc'
            else:
                continue

            self.compiler = compiler, version

    def __register_section_symbols(self, sec_re):
        for sym_re in sec_re.iter_symbols():
            self.symbols.add(self.get_symbol(sym_re))

    def __relocate_mips(self, symtab):
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
            symbol = self.get_symbol(i + symtab_got_idx, symtab)
            reloc = MipsGlobalReloc(self, symbol, gotaddr + (i + got_local_num)*wordsize)
            self.relocs.append(reloc)
            self.jmprel[symbol.name] = reloc
        return True

    def __neuter_streams(self, obj):
        if isinstance(obj, elftools.elf.dynamic._DynamicStringTable):
           obj._stream = self.memory
           obj._table_offset = self._offset_to_rva(obj._table_offset)
        elif isinstance(obj, elftools.elf.sections.Section):
            if obj.header.sh_type == 'SHT_NOBITS':
                obj.stream = None
                obj.elffile = None
                obj.header.sh_offset = None
            else:
                obj.stream = self.memory
                obj.elffile = None
                obj.header.sh_offset = self._offset_to_rva(obj.header.sh_offset)
        else:
            raise TypeError("Can't convert %r" % type(obj))

    def _offset_to_rva(self, offset):
        return AT.from_mva(self.offset_to_addr(offset), self).to_rva()

    def __process_debug_file(self, filename):
        with open(filename, 'rb') as fp:
            try:
                elf = elffile.ELFFile(fp)
            except ELFError:
                l.warning("pyelftools failed to load debug file %s", filename, exc_info=True)
                return

            for sec_readelf in elf.iter_sections():
                if isinstance(sec_readelf, elffile.SymbolTableSection):
                    self.__register_section_symbols(sec_readelf)
                elif sec_readelf.header.sh_type == 'SHT_NOTE':
                    self.__register_notes(sec_readelf)

            #has_dwarf_info = bool(elf.has_dwarf_info())
            #if has_dwarf_info:
            #    try:
            #        dwarf = self.reader.get_dwarf_info()
            #    except ELFError:
            #        l.warning("An exception occurred in pyelftools when loading the DWARF information on %s.", filename,
            #                  exc_info=True)
            #        dwarf = None

                # debug symbols don't have eh_frame ever from what I can tell
                #if dwarf and dwarf.has_EH_CFI():
                #    self._load_function_hints_from_fde(dwarf, FunctionHintSource.EXTERNAL_EH_FRAME)


register_backend('elf', ELF)
