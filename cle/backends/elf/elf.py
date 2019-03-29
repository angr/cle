import os
import struct
import subprocess
import logging
import archinfo
import elftools
from elftools.elf import elffile, sections
from collections import OrderedDict, defaultdict

from .symbol import ELFSymbol, Symbol
from .regions import ELFSection, ELFSegment
from .hashtable import ELFHashTable, GNUHashTable
from .metaelf import MetaELF, maybedecode
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
    is_default = True  # Tell CLE to automatically consider using the ELF backend

    def __init__(self, binary, addend=None, **kwargs):
        super(ELF, self).__init__(binary, **kwargs)
        patch_undo = []
        try:
            self.reader = elffile.ELFFile(self.binary_stream)
            list(self.reader.iter_sections())
        except Exception: # pylint: disable=broad-except
            self.binary_stream.seek(4)
            ty = self.binary_stream.read(1)
            if ty not in (b'\1', b'\2'):
                raise CLECompatibilityError

            if ty == b'\1':
                patch_data = [(0x20, b'\0'*4), (0x2e, b'\0'*6)]
            else:
                patch_data = [(0x28, b'\0'*8), (0x3a, b'\0'*6)]

            for offset, patch in patch_data:
                self.binary_stream.seek(offset)
                patch_undo.append((offset, self.binary_stream.read(len(patch))))

            self.binary_stream = PatchedStream(self.binary_stream, patch_data)
            l.error("PyReadELF couldn't load this file. Trying again without section headers...")

            try:
                self.reader = elffile.ELFFile(self.binary_stream)
            except Exception as e: # pylint: disable=broad-except
                raise CLECompatibilityError from e

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
        self._desperate_for_symbols = False
        self.demangled_names = {}
        self.imports = {}
        self.resolved_imports = []

        self.relocs = []
        self.jmprel = OrderedDict()

        self._entry = self.reader.header.e_entry
        self.is_relocatable = self.reader.header.e_type == 'ET_REL'
        self.pic = self.pic or self.reader.header.e_type in ('ET_REL', 'ET_DYN')

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
            l.warning('no segments identified in PT_LOAD')

        self.__register_segments()
        self.__register_sections()

        if not self.symbols:
            self._desperate_for_symbols = True
            self.symbols.update(self._symbol_cache.values())

        # call the methods defined by MetaELF
        self._ppc64_abiv1_entry_fix()
        self._load_plt()

        self._populate_demangled_names()

        for offset, patch in patch_undo:
            self.memory.store(AT.from_lva(self.min_addr + offset, self).to_rva(), patch)



    #
    # Properties and Public Methods
    #

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
        if symbol_table is None:
            symbol_table = self.dynsym

        if type(symid) is int:
            if symid == 0:
                # special case the null symbol, this is important for static binaries
                return self._nullsymbol
            try:
                re_sym = symbol_table.get_symbol(symid)
            except Exception: # pylint: disable=bare-except
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
            l.warning("ELF file %s is loading a segment with an inappropriate alignment. It might not work in all contexts.", self.binary)
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
                data = data[:zero - mapstart].ljust(zeropage - mapstart, b'\0')

            zeroend = ALIGN_UP(allocend, self.loader.page_size) # mmap maps to the next page boundary
            if zeroend > zeropage:
                data = data.ljust(zeroend - mapstart, b'\0')

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

        if not self.symbols:
            return

        names = [s.name for s in self.symbols if s.name.startswith("_Z")]
        # this monstrosity taken from stackoverflow
        # http://stackoverflow.com/questions/6526500/c-name-mangling-library-for-python
        args = ['c++filt']
        args.extend(n.split('@@')[0] for n in names)
        try:
            pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            demangled = stdout.decode().split("\n")[:-1]

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

        state = dict(self.__dict__)

        # Trash the unpickleable
        if type(self.binary_stream) is PatchedStream:
            state['binary_stream'].stream = None
        else:
            state['binary_stream'] = None

        state['reader'] = None
        state['strtab'] = None
        state['dynsym'] = None
        state['hashtable'] = None

        return state

    def __setstate__(self, data):
        self.__dict__.update(data)

        if self.binary_stream is None:
            self.binary_stream = open(self.binary, 'rb')
        else:
            self.binary_stream.stream = open(self.binary, 'rb')

        self.reader = elffile.ELFFile(self.binary_stream)
        if self._dynamic and 'DT_STRTAB' in self._dynamic:
            self.strtab = next(x for x in self.reader.iter_segments() if x.header.p_type == 'PT_DYNAMIC')._get_stringtable()
            if 'DT_SYMTAB' in self._dynamic and 'DT_SYMENT' in self._dynamic:
                fakesymtabheader = {
                    'sh_offset': AT.from_lva(self._dynamic['DT_SYMTAB'], self).to_rva(),
                    'sh_entsize': self._dynamic['DT_SYMENT'],
                    'sh_size': 0, # bogus size: no iteration allowed
                    'sh_flags': 0,
                    'sh_addralign': 0,
                }
                self.dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.reader, self.strtab)
                self.dynsym.stream = self.memory

                if 'DT_GNU_HASH' in self._dynamic:
                    self.hashtable = GNUHashTable(
                            self.dynsym,
                            self.memory,
                            AT.from_lva(self._dynamic['DT_GNU_HASH'], self).to_rva(),
                            self.arch)
                elif 'DT_HASH' in self._dynamic:
                    self.hashtable = ELFHashTable(
                            self.dynsym,
                            self.memory,
                            AT.from_lva(self._dynamic['DT_HASH'], self).to_rva(),
                            self.arch)

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

        self.strtab = seg_readelf._get_stringtable()

        # To extract symbols from binaries without section headers, we need to hack into pyelftools.
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
                self.dynsym = elffile.SymbolTableSection(fakesymtabheader, 'symtab_cle', self.reader, self.strtab)
                self.dynsym.stream = self.memory

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
                    readelf_relocsec = elffile.RelocationSection(fakerelheader, 'reloc_cle', self.reader)
                    readelf_relocsec.stream = self.memory
                    self.__register_relocs(readelf_relocsec)

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
                    readelf_jmprelsec = elffile.RelocationSection(fakejmprelheader, 'jmprel_cle', self.reader)
                    readelf_jmprelsec.stream = self.memory
                    self.__register_relocs(readelf_jmprelsec, force_jmprel=True)

    def __parse_rpath(self, runpath, rpath):
        """
        Split RPATH/RUNPATH tags into a list of paths while expanding rpath tokens.
        """
        # DT_RUNPATH takes predence over DT_RPATH
        if len(runpath) > 0:
            runpath = runpath
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

    def __register_relocs(self, section, force_jmprel=False):

        got_min = got_max = 0

        if not force_jmprel:
            got_sec = self.reader.get_section_by_name('.got')
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

        symtab = self.reader.get_section(section.header['sh_link']) if 'sh_link' in section.header else None
        if isinstance(symtab, elftools.elf.sections.NullSection):
            # Oh my god Atmel please stop
            symtab = self.reader.get_section_by_name('.symtab')
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
                        self.memory.add_backer(AT.from_lva(section.vaddr, self).to_rva(), b'\0'*sec_readelf.header['sh_size'])
                    else: #elif section.type == 'SHT_PROGBITS':
                        self.memory.add_backer(AT.from_lva(section.vaddr, self).to_rva(), sec_readelf.data())

    def __register_section_symbols(self, sec_re):
        for sym_re in sec_re.iter_symbols():
            self.symbols.add(self.get_symbol(sym_re))

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
