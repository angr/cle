# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).
from collections import defaultdict
from os import SEEK_CUR, SEEK_SET
import struct
import sys
from io import BytesIO, BufferedReader
from typing import Optional, DefaultDict, List, Tuple


import archinfo

from .section import MachOSection
from .symbol import SymbolTableSymbol, AbstractMachOSymbol
from .segment import MachOSegment
from .binding import BindingHelper, read_uleb
from .. import Backend, register_backend, AT
from ...errors import CLEInvalidBinaryError, CLECompatibilityError, CLEOperationError

import logging
l = logging.getLogger(name=__name__)

__all__ = ('MachO', 'MachOSection', 'MachOSegment')

from sortedcontainers import SortedKeyList

# pylint: disable=abstract-method
class SymbolList(SortedKeyList):
    _symbol_cache: DefaultDict[Tuple[str, int],
                               List[AbstractMachOSymbol]]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._symbol_cache = defaultdict(list)

    def add(self, value: AbstractMachOSymbol):
        super().add(value)
        self._symbol_cache[(value.name, value.library_ordinal,)].append(value)

    def get_by_name_and_ordinal(self, name: str, ordinal: int, include_stab=False) -> List[AbstractMachOSymbol]:
        if include_stab:
            return self._symbol_cache[(name, ordinal)]
        else:
            return [symbol for symbol in self._symbol_cache[(name, ordinal)] if not symbol.is_stab]

# pylint: enable =abstract-method



class MachO(Backend):
    """
    Mach-O binaries for CLE

    The Mach-O format is notably different from other formats, as such:
    *   Sections are always part of a segment, self.sections will thus be empty
    *   Symbols cannot be categorized like in ELF
    *   Symbol resolution must be handled by the binary
    *   Rebasing cannot be done statically (i.e. self.mapped_base is ignored for now)
    *   ...
    """
    is_default = True # Tell CLE to automatically consider using the MachO backend

    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe
    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe


    def __init__(self, *args, **kwargs):
        l.warning('The Mach-O backend is not well-supported. Good luck!')

        super().__init__(*args, **kwargs)
        self.symbols = SymbolList(key=self._get_symbol_relative_addr)

        self.struct_byteorder = None  # holds byteorder for struct.unpack(...)
        self._mapped_base = None # temporary holder für mapped base derived via loading
        self.cputype = None
        self.cpusubtype = None
        self.filetype = None
        self.pie = None  # position independent executable?
        self.ncmds = None  # number of load commands
        self.flags = None  # binary flags
        self.sizeofcmds = None  # total size of load commands
        self.imported_libraries = ["Self"]  # ordinal 0 = SELF_LIBRARY_ORDINAL
        self.sections_by_ordinal = [None] # ordinal 0 = None == Self
        self.exports_by_name = {}  # note exports is currently a raw and unprocessed datastructure.
        # If we intend to use it we must first upgrade it to a class or somesuch
        self.entryoff = None
        self.unixthread_pc = None
        self.os = "macos"
        self.lc_data_in_code = []  # data from LC_DATA_IN_CODE (if encountered). Format: (offset,length,kind)
        self.mod_init_func_pointers = []  # may be TUMB interworking
        self.mod_term_func_pointers = []  # may be THUMB interworking
        self.export_blob = None  # exports trie
        self.binding_blob: Optional[bytes] = None  # binding information
        self.lazy_binding_blob: Optional[bytes] = None  # lazy binding information
        self.weak_binding_blob: Optional[bytes] = None  # weak binidng information
        self.symtab_offset = None # offset to the symtab
        self.symtab_nsyms = None # number of symbols in the symtab
        self.binding_done = False # if true binding was already done and do_bind will be a no-op

        # For some analysis the insertion order of the symbols is relevant and needs to be kept.
        # This is has to be separate from self.symbols because the latter is sorted by address
        self._ordered_symbols = []

        # Begin parsing the file
        try:

            binary_file = self._binary_stream
            # get magic value and determine endianness
            self.struct_byteorder = self._detect_byteorder(struct.unpack("=I", binary_file.read(4))[0])

            # parse the mach header:
            # (ignore all irrelevant fiels)
            self._parse_mach_header(binary_file)

            # determine architecture
            arch_ident = self._detect_arch_ident()
            if not arch_ident:
                raise CLECompatibilityError(
                    "Unsupported architecture: 0x{0:X}:0x{1:X}".format(self.cputype, self.cpusubtype))

            # Create archinfo
            # Note that this should be customized for Apple ABI (TODO)
            self.set_arch(
                archinfo.arch_from_id(arch_ident, endness="lsb" if self.struct_byteorder == "<" else "msb"))

            # Start reading load commands
            lc_offset = (7 if self.arch.bits == 32 else 8) * 4

            # Possible optimization: Remove all unecessary calls to seek()
            # Load commands have a common structure: First 4 bytes identify the command by a magic number
            # second 4 bytes determine the commands size. Everything after this generic "header" is command-specific
            # this makes parsing the commands easy.
            # The documentation for Mach-O is at http://opensource.apple.com//source/xnu/xnu-1228.9.59/EXTERNAL_HEADERS/mach-o/loader.h
            count = 0
            offset = lc_offset
            while count < self.ncmds and (offset - lc_offset) < self.sizeofcmds:
                count += 1
                (cmd, size) = self._unpack("II", binary_file, offset, 8)

                # check for segments that interest us
                if cmd in [0x1, 0x19]:  # LC_SEGMENT,LC_SEGMENT_64
                    l.debug("Found LC_SEGMENT(_64) @ %#x", offset)
                    self._load_segment(binary_file, offset)
                elif cmd == 0x2:  # LC_SYMTAB
                    l.debug("Found LC_SYMTAB @ %#x", offset)
                    self._load_symtab(binary_file, offset)
                elif cmd in [0x22, 0x80000022]:  # LC_DYLD_INFO(_ONLY)
                    l.debug("Found LC_DYLD_INFO(_ONLY) @ %#x", offset)
                    self._load_dyld_info(binary_file, offset)
                elif cmd in [0xc, 0x8000001c, 0x80000018]:  # LC_LOAD_DYLIB, LC_REEXPORT_DYLIB,LC_LOAD_WEAK_DYLIB
                    l.debug("Found LC_*_DYLIB @ %#x", offset)
                    self._load_dylib_info(binary_file, offset)
                elif cmd == 0x80000028:  # LC_MAIN
                    l.debug("Found LC_MAIN @ %#x", offset)
                    self._load_lc_main(binary_file, offset)
                elif cmd == 0x5:  # LC_UNIXTHREAD
                    l.debug("Found LC_UNIXTHREAD @ %#x", offset)
                    self._load_lc_unixthread(binary_file, offset)
                elif cmd == 0x26:  # LC_FUNCTION_STARTS
                    l.debug("Found LC_FUNCTION_STARTS @ %#x", offset)
                    self._load_lc_function_starts(binary_file, offset)
                elif cmd == 0x29:  # LC_DATA_IN_CODE
                    l.debug("Found LC_DATA_IN_CODE @ %#x", offset)
                    self._load_lc_data_in_code(binary_file, offset)
                elif cmd in [0x21, 0x2c]:  # LC_ENCRYPTION_INFO(_64)
                    l.debug("Found LC_ENCRYPTION_INFO @ %#x", offset)
                    self._assert_unencrypted(binary_file, offset)

                # update bookkeeping
                offset += size

            # Assertion to catch malformed binaries - YES this is needed!
            if count < self.ncmds or (offset - lc_offset) < self.sizeofcmds:
                raise CLEInvalidBinaryError(
                    "Assertion triggered: {0} < {1} or {2} < {3}".format(count, self.ncmds, (offset - lc_offset),
                                                                         self.sizeofcmds))
        except IOError as e:
            l.exception(e)
            raise CLEOperationError(e)

        # File is read, begin populating internal fields
        self._resolve_entry()
        self._parse_exports()
        self._parse_symbols(binary_file)
        self._parse_mod_funcs()

        text_segment = self.find_segment_by_name("__TEXT")
        if not text_segment is None:
            self.mapped_base = text_segment.vaddr
        else:
            l.warning("No text segment found")

        self.do_binding()

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x5)
        stream.seek(0)
        if identstring.startswith(struct.pack('I', MachO.MH_MAGIC_64)) or \
           identstring.startswith(struct.pack('I', MachO.MH_CIGAM_64)) or \
           identstring.startswith(struct.pack('I', MachO.MH_MAGIC)) or \
           identstring.startswith(struct.pack('I', MachO.MH_CIGAM)):
            return True
        return False

    def is_thumb_interworking(self, address):
        """Returns true if the given address is a THUMB interworking address"""
        # Note: Untested
        return self.arch.bits != 64 and address & 1

    def decode_thumb_interworking(self, address):
        """Decodes a thumb interworking address"""
        # Note: Untested
        return address & ~1 if self.is_thumb_interworking(address) else address

    def _parse_mod_funcs(self):
        l.debug("Parsing module init/term function pointers")

        fmt = "Q" if self.arch.bits == 64 else "I"
        size = 8 if self.arch.bits == 64 else 4

        # factoring out common code
        def parse_mod_funcs_internal(s, target):
            for i in range(s.vaddr, s.vaddr + s.memsize, size):
                addr = self._unpack_with_byteorder(fmt, self.memory.load(i, size))[0]
                l.debug("Addr: %#x", addr)
                target.append(addr)

        for seg in self.segments:
            for sec in seg.sections:

                if sec.type == 0x9:  # S_MOD_INIT_FUNC_POINTERS
                    l.debug("Section %s contains init pointers", sec.sectname)
                    parse_mod_funcs_internal(sec, self.mod_init_func_pointers)
                elif sec.type == 0xa:  # S_MOD_TERM_FUNC_POINTERS
                    l.debug("Section %s contains term pointers", sec.sectname)
                    parse_mod_funcs_internal(sec, self.mod_term_func_pointers)

        l.debug("Done parsing module init/term function pointers")

    def find_segment_by_name(self, name):
        for s in self.segments:
            if s.segname == name:
                return s
        return None

    def _resolve_entry(self):
        if self.entryoff:
            self._entry = self.entryoff
        elif self.unixthread_pc:
            self._entry = self.unixthread_pc
        else:
            l.warning("No entry point found")
            self._entry = 0

    @staticmethod
    def _read(fp: BufferedReader, offset: int, size: int) -> bytes:
        """
        Simple read abstraction, reads size bytes from offset in file
        :param offset: Offset to seek() to
        :param size: number of bytes to be read
        :return: string of bytes or "" for EOF
        """
        fp.seek(offset)
        return fp.read(size)

    def _unpack_with_byteorder(self, fmt, data):
        """
        Appends self.struct_byteorder before fmt to ensure usage of correct byteorder
        :return: struct.unpack(self.struct_byteorder+fmt,input)
        """
        return struct.unpack(self.struct_byteorder + fmt, data)

    def _unpack(self, fmt, fp, offset, size):
        """Convenience"""
        return self._unpack_with_byteorder(fmt, self._read(fp, offset, size))

    def _parse_mach_header(self, f):
        """
        Parses the mach-o header and sets
        self.cputype, self.cpusubtype, self.pie, self.ncmds,self.flags,self.sizeofcmds and self.filetype

        Currently ignores any type of information that is not directly relevant to analyses
        :param f: The binary as a file object
        :return: None
        """
        # this method currently disregards any differences between 32 and 64 bit code
        (_, self.cputype, self.cpusubtype, self.filetype, self.ncmds, self.sizeofcmds,
         self.flags) = self._unpack("7I", f, 0, 28)

        self.pie = bool(self.flags & 0x200000)  # MH_PIE

        if not bool(self.flags & 0x80):  # ensure MH_TWOLEVEL
            l.error("Binary is not using MH_TWOLEVEL namespacing. This isn't properly implemented yet and will degrade results in unpredictable ways. Please open an issue if you encounter this with a binary you can share")

    @staticmethod
    def _detect_byteorder(magic):
        """Determines the binary's byteorder """

        l.debug("Magic is %#x", magic)

        host_is_little = sys.byteorder == 'little'

        if host_is_little:
            if magic in [MachO.MH_MAGIC_64, MachO.MH_MAGIC]:
                l.debug("Detected little-endian")
                return "<"
            elif magic in [MachO.MH_CIGAM, MachO.MH_CIGAM_64]:
                l.debug("Detected big-endian")
                return ">"
            else:
                l.debug("Not a mach-o file")
                raise CLECompatibilityError()
        else:
            if magic in [MachO.MH_MAGIC_64, MachO.MH_MAGIC]:
                l.debug("Detected big-endian")
                return ">"
            elif magic in [MachO.MH_CIGAM_64, MachO.MH_CIGAM]:
                l.debug("Detected little-endian")
                return "<"
            else:
                l.debug("Not a mach-o file")
                raise CLECompatibilityError()


    def do_binding(self):
        # Perform binding

        if self.binding_done:
            l.warning("Binding already done, reset self.binding_done to override if you know what you are doing")
            return

        bh = BindingHelper(self)  # TODO: Make this configurable
        bh.do_normal_bind(self.binding_blob)
        bh.do_lazy_bind(self.lazy_binding_blob)
        if self.weak_binding_blob is not None and len(self.weak_binding_blob) > 0:
            l.info("Found weak binding blob. According to current state of knowledge, weak binding "
                   "is only sensible if multiple binaries are involved and is thus skipped.")


        self.binding_done=True


    def _parse_exports(self):
        """
        Parses the exports trie
        """
        l.debug("Parsing exports")
        blob = self.export_blob
        if blob is None:
            l.debug("Parsing exports done: No exports found")
            return

        # Note some of these fields are currently not used, keep them in to make used variables explicit
        index = 0
        sym_str = b''
        # index,str
        nodes_to_do = [(0, b'')]
        blob_f = BytesIO(blob)  # easier to handle seeking here

        # constants
        #FLAGS_KIND_MASK = 0x03
        #FLAGS_KIND_REGULAR = 0x00
        #FLAGS_KIND_THREAD_LOCAL = 0x01
        #FLAGS_WEAK_DEFINITION = 0x04
        FLAGS_REEXPORT = 0x08
        FLAGS_STUB_AND_RESOLVER = 0x10

        try:
            while True:
                index, sym_str = nodes_to_do.pop()
                l.debug("Processing node %#x %r", index, sym_str)
                blob_f.seek(index, SEEK_SET)
                info_len = struct.unpack("B", blob_f.read(1))[0]
                if info_len > 127:
                    # special case
                    blob_f.seek(-1, SEEK_CUR)
                    tmp = read_uleb(blob, blob_f.tell())  # a bit kludgy
                    info_len = tmp[0]
                    blob_f.seek(tmp[1], SEEK_CUR)

                if info_len > 0:
                    # a symbol is complete
                    tmp = read_uleb(blob, blob_f.tell())
                    blob_f.seek(tmp[1], SEEK_CUR)
                    flags = tmp[0]
                    if flags & FLAGS_REEXPORT:
                        # REEXPORT: uleb:lib ordinal, zero-term str
                        tmp = read_uleb(blob, blob_f.tell())
                        blob_f.seek(tmp[1], SEEK_CUR)
                        lib_ordinal = tmp[0]
                        lib_sym_name = b''
                        char = blob_f.read(1)
                        while char != b'\0':
                            lib_sym_name += char
                            char = blob_f.read(1)
                        l.info("Found REEXPORT export %r: %d,%r", sym_str, lib_ordinal, lib_sym_name)
                        self.exports_by_name[sym_str.decode()] = (flags, lib_ordinal, lib_sym_name.decode())
                    elif flags & FLAGS_STUB_AND_RESOLVER:
                        # STUB_AND_RESOLVER: uleb: stub offset, uleb: resovler offset
                        l.warning("EXPORT: STUB_AND_RESOLVER found")
                        tmp = read_uleb(blob, blob_f.tell())
                        blob_f.seek(tmp[1], SEEK_CUR)
                        stub_offset = tmp[0]
                        tmp = read_uleb(blob, blob_f.tell())
                        blob_f.seek(tmp[1], SEEK_CUR)
                        resolver_offset = tmp[0]
                        l.info("Found STUB_AND_RESOLVER export %r: %#x,%#x'", sym_str, stub_offset, resolver_offset)
                        self.exports_by_name[sym_str.decode()] = (flags, stub_offset, resolver_offset)
                    else:
                        # normal: offset from mach header
                        tmp = read_uleb(blob, blob_f.tell())
                        blob_f.seek(tmp[1], SEEK_CUR)
                        symbol_offset = tmp[0] + self.segments[1].vaddr
                        l.info("Found normal export %r: %#x", sym_str, symbol_offset)
                        self.exports_by_name[sym_str.decode()] = (flags, symbol_offset)

                child_count = struct.unpack("B", blob_f.read(1))[0]
                for i in range(0, child_count):
                    child_str = sym_str
                    char = blob_f.read(1)
                    while char != b'\0':
                        child_str += char
                        char = blob_f.read(1)
                    tmp = read_uleb(blob, blob_f.tell())
                    blob_f.seek(tmp[1], SEEK_CUR)
                    next_node = tmp[0]
                    l.debug("%d. child: (%#x, %r)", i, next_node, child_str)
                    nodes_to_do.append((next_node, child_str))

        except IndexError:
            # List is empty we are done!
            l.debug("Done parsing exports")

    def _detect_arch_ident(self):
        """
        Determines the binary's architecture by inspecting cputype and cpusubtype.
        :return: archinfo.arch_from_id-compatible ident string
        """
        # determine architecture by major CPU type
        try:
            arch_lookup = {
            # contains all supported architectures. Note that apple deviates from standard ABI, see Apple docs
                0x100000c: "aarch64",
                0xc: "arm",
                0x7: "x86",
                0x1000007: "x64",
            }
            return arch_lookup[self.cputype]  # subtype currently not needed
        except KeyError:
            return None

    def _load_lc_data_in_code(self, f, off):
        l.debug("Parsing data in code")

        (_, _, dataoff, datasize) = self._unpack("4I", f, off, 16)
        for i in range(dataoff, datasize, 8):
            blob = self._unpack("IHH", f, i, 8)
            self.lc_data_in_code.append(blob)

        l.debug("Done parsing data in code")

    def _assert_unencrypted(self, f, off):
        l.debug("Asserting unencrypted file")
        (_, _, _, _, cryptid) = self._unpack("5I", f, off, 20)
        if cryptid > 0:
            l.error("Cannot load encrypted files")
            raise CLEInvalidBinaryError()

    def _load_lc_function_starts(self, f, off):
        # note that the logic below is based on Apple's dyldinfo.cpp, no official docs seem to exist
        l.debug("Parsing function starts")
        (_, _, dataoff, datasize) = self._unpack("4I", f, off, 16)

        i = 0
        end = datasize
        blob = self._read(f, dataoff, datasize)
        self.lc_function_starts = []

        address = None
        for seg in self.segments:
            if seg.offset == 0 and seg.filesize != 0:
                address = seg.vaddr
                break

        if address is None:
            l.error("Could not determine base-address for function starts")
            raise CLEInvalidBinaryError()
        l.debug("Located base-address: %#x", address)

        while i < end:
            uleb = read_uleb(blob, i)

            if blob[i] == 0:
                break  # list is 0 terminated

            address += uleb[0]

            self.lc_function_starts.append(address)
            l.debug("Function start @ %#x (%#x)", uleb[0],address)
            i += uleb[1]
        l.debug("Done parsing function starts")

    def _load_lc_main(self, f, offset):
        if self.entryoff is not None or self.unixthread_pc is not None:
            l.error("More than one entry point for main detected, abort.")
            raise CLEInvalidBinaryError()

        (_, _, self.entryoff, _) = self._unpack("2I2Q", f, offset, 24)
        l.debug("LC_MAIN: entryoff=%#x", self.entryoff)

    def _load_lc_unixthread(self, f, offset):
        if self.entryoff is not None or self.unixthread_pc is not None:
            l.error("More than one entry point for main detected, abort.")
            raise CLEInvalidBinaryError()

        # parse basic structure
        # _, cmdsize, flavor, long_count
        _, _, flavor, _ = self._unpack("4I", f, offset, 16)

        # we only support 4 different types of thread state atm
        # TODO: This is the place to add x86 and x86_64 thread states
        if flavor == 1 and self.arch.bits != 64:  # ARM_THREAD_STATE or ARM_UNIFIED_THREAD_STATE or ARM_THREAD_STATE32
            blob = self._unpack("16I", f, offset + 16, 64)  # parses only until __pc
        elif flavor == 1 and self.arch.bits == 64 or flavor == 6:  # ARM_THREAD_STATE or ARM_UNIFIED_THREAD_STATE or ARM_THREAD_STATE64
            blob = self._unpack("33Q", f, offset + 16, 264)  # parses only until __pc
        else:
            l.error("Unknown thread flavor: %d", flavor)
            raise CLECompatibilityError()

        self.unixthread_pc = blob[-1]
        l.debug("LC_UNIXTHREAD: __pc=%#x", self.unixthread_pc)

    def _load_dylib_info(self, f, offset):
        (_, _, name_offset, _, _, _) = self._unpack("6I", f, offset, 24)
        lib_name = self.parse_lc_str(f, offset + name_offset)
        l.debug("Adding library %r", lib_name)
        self.imported_libraries.append(lib_name)

    def _load_dyld_info(self, f: BufferedReader, offset):
        """
        Extracts information blobs for rebasing, binding and export
        """
        (_, _, roff, rsize, boff, bsize, wboff, wbsize, lboff, lbsize, eoff, esize) = self._unpack("12I", f, offset, 48)

        def blob_or_None(f: BufferedReader, off: int, size: int ) -> Optional[bytes]:  # helper
            return self._read(f,off,size) if off != 0 and size != 0 else None

        # Extract data blobs
        self.rebase_blob = blob_or_None(f, roff, rsize)
        self.binding_blob = blob_or_None(f, boff, bsize)
        self.weak_binding_blob = blob_or_None(f, wboff, wbsize)
        self.lazy_binding_blob = blob_or_None(f, lboff, lbsize)
        self.export_blob = blob_or_None(f, eoff, esize)

    def _load_symtab(self, f, offset):
        """
        Handles loading of the symbol table
        :param f: input file
        :param offset: offset to the LC_SYMTAB structure
        :return:
        """

        (_, _, symoff, nsyms, stroff, strsize) = self._unpack("6I", f, offset, 24)

        # load string table
        self.strtab = self._read(f, stroff, strsize)

        # store symtab info
        self.symtab_nsyms = nsyms
        self.symtab_offset = symoff

    def _parse_symbols(self,f):

        # parse the symbol entries and create (unresolved) MachOSymbols.
        if self.arch.bits == 64:
            packstr = "I2BHQ"
            structsize = 16
        else:
            packstr = "I2BhI"
            structsize = 12

        for i in range(0, self.symtab_nsyms):
            offset_in_symtab = (i * structsize)
            offset = offset_in_symtab+ self.symtab_offset
            (n_strx, n_type, n_sect, n_desc, n_value) = self._unpack(packstr, f, offset, structsize)
            l.debug("Adding symbol # %d @ %#x: %s,%s,%s,%s,%s",
                    i, offset,
                    n_strx, n_type, n_sect, n_desc, n_value)
            sym = SymbolTableSymbol(
                    self, offset_in_symtab, n_strx, n_type, n_sect, n_desc, n_value)
            self.symbols.add(sym)
            self._ordered_symbols.append(sym)

            l.debug("Symbol # %d @ %#x is '%s'",i,offset, sym.name)

    def get_string(self, start):
        """Loads a string from the string table"""
        end = start
        if end > len(self.strtab):
            raise ValueError()

        while end < len(self.strtab):
            if self.strtab[end] == 0:
                return self.strtab[start:end]
            end += 1
        return self.strtab[start:]

    def parse_lc_str(self, f, start, limit=None):
        """Parses a lc_str data structure"""
        tmp = self._unpack("c", f, start, 1)[0]
        s = b''
        ctr = 0
        while tmp != b'\0' and (limit is None or ctr < limit):
            s += tmp
            ctr += 1
            tmp = self._unpack("c", f, start + ctr, 1)[0]

        return s

    def _load_segment(self, f, offset):
        """
        Handles LC_SEGMENT(_64) commands
        :param f: input file
        :param offset: starting offset of the LC_SEGMENT command
        :return:
        """
        # determine if 64 or 32 bit segment
        is64 = self.arch.bits == 64
        if not is64:
            segment_s_size = 56
            (_, _, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags) = self._unpack(
                "2I16s8I", f, offset, segment_s_size)
        else:
            segment_s_size = 72
            (_, _, segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, flags) = self._unpack(
                "2I16s4Q4I", f, offset, segment_s_size)

        # Cleanup segname
        segname = segname.replace(b'\0', b'')
        l.debug("Processing segment %r", segname)

        # create segment
        seg = MachOSegment(fileoff, vmaddr, filesize, vmsize, segname, nsects, [], flags, initprot, maxprot)

        # Parse section datastructures
        if not is64:
            # 32 bit
            section_s_size = 68
            section_s_packstr = "16s16s9I"
        else:
            # 64 bit
            section_s_size = 80
            # The correct packstring is "16s16s2Q8I", however we use a different one that merges the last two reserved
            # fields (reserved2,reserved3) because it makes the parsing logic below easier
            section_s_packstr = "16s16s2Q6IQ"

        section_start = offset + segment_s_size
        for i in range(0, nsects):
            # Read section
            l.debug("Processing section # %d in %r", i + 1, segname)
            (section_sectname, section_segname, section_vaddr, section_vsize, section_foff, section_align,
             section_reloff,
             section_nreloc, section_flags, r1, r2) = \
                self._unpack(section_s_packstr, f, (i * section_s_size) + section_start, section_s_size)

            # Clean segname and sectname
            section_sectname = section_sectname.replace(b'\0', b'')
            section_segname = section_segname.replace(b'\0', b'')

            # Create section
            sec = MachOSection(section_foff, section_vaddr, section_vsize, section_vsize, section_segname,
                               section_sectname,
                               section_align, section_reloff, section_nreloc, section_flags, r1, r2)

            # Store section
            seg.sections.append(sec)

        # add to sections_by_ordinal
        self.sections_by_ordinal.extend(seg.sections)

        if segname == b"__PAGEZERO":
            # TODO: What we actually need at this point is some sort of smart on-demand string or memory
            # This should not cause trouble because accesses to __PAGEZERO are SUPPOSED to crash (segment has access set to no access)
            # This optimization is here as otherwise several GB worth of zeroes would clutter our memory
            l.info("Found PAGEZERO, skipping backer for memory conservation")
        elif seg.filesize > 0:
            # Append segment data to memory
            blob = self._read(f, seg.offset, seg.filesize)
            if seg.filesize < seg.memsize:
                blob += b'\0' * (seg.memsize - seg.filesize)  # padding

            # for some reason seg.offset is not always the same as seg.vaddr - baseaddress
            # when they differ the vaddr seems to be the correct choice according to loaders like in Ghidra
            # but there isn't necessarily a clear definition of a baseaddress because the vmaddr just specifies the the address in the global memory space
            vaddr_offset = AT.from_mva(seg.vaddr, self).to_rva()
            self.memory.add_backer(vaddr_offset, blob)

        # Store segment
        self.segments.append(seg)

    def get_symbol_by_address_fuzzy(self, address):
        """
        Locates a symbol by checking the given address against sym.addr, sym.bind_xrefs and
        sym.symbol_stubs
        """
        for sym in self.symbols:
            if address == sym.relative_addr or address in sym.bind_xrefs or address in sym.symbol_stubs:
                return sym
        return None

    def get_symbol(self, name, include_stab=False, fuzzy=False): # pylint: disable=arguments-differ
        """
        Returns all symbols matching name.

        Note that especially when include_stab=True there may be multiple symbols with the same
        name, therefore this method always returns an array.

        :param name: the name of the symbol
        :param include_stab: Include debugging symbols NOT RECOMMENDED
        :param fuzzy: Replace exact match with "contains"-style match
        """
        result = []
        for sym in self.symbols:

            if sym.is_stab and not include_stab:
                continue

            if fuzzy:
                if name in sym.name:
                    result.append(sym)
            else:
                if name == sym.name:
                    result.append(sym)

        return result

    def get_symbol_by_insertion_order(self, idx: int) -> AbstractMachOSymbol:
        """

        :param idx: idx when this symbol was inserted
        :return:
        """
        return self._ordered_symbols[idx]

    def get_segment_by_name(self, name):
        """
        Searches for a MachOSegment with the given name and returns it
        :param name: Name of the sought segment
        :return: MachOSegment or None
        """
        for seg in self.segments:
            if seg.segname == name:
                return seg

        return None

    def __getitem__(self, item):
        """
        Syntactic sugar for get_segment_by_name
        """
        return self.get_segment_by_name(item)


register_backend('mach-o', MachO)
