# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).

from os import SEEK_CUR, SEEK_SET
import struct
import sys
from io import BytesIO
import archinfo

from macholib import MachO as MachOLoader
from macholib import SymbolTable as MachOLoaderSymbolTable
from .section import MachOSection
from .symbol import SymbolTableSymbol
from .segment import MachOSegment
from .binding import BindingHelper, read_uleb
from .. import Backend, register_backend
from ...utils import stream_or_path
from ...errors import CLEInvalidBinaryError, CLECompatibilityError, CLEOperationError, CLEError

import logging
l = logging.getLogger('cle.backends.macho')

__all__ = ('MachO', 'MachOSection', 'MachOSegment')

# The documentation for Mach-O is at http://opensource.apple.com//source/xnu/xnu-1228.9.59/EXTERNAL_HEADERS/mach-o/loader.h

# TODO:
# Handle loading corefile; corefiles in macos don't indicate where
#   fs_base/gs_base is, so user will have to manually indicate
# In the future, possibly add support for full_init_state, which will just
#   execute the dyld code; unsure if can bypass dyld trying to load dependencies

class MachO(Backend):
    """
    Mach-O binaries for CLE

    The Mach-O format is notably different from other formats, as such:
    *   Sections are always part of a segment, self.sections will thus be empty
    *   Symbols cannot be categorized like in ELF
    *   Symbol resolution must be handled by the binary
    *   Rebasing cannot be done statically (i.e. self.mapped_base is ignored for now)
    *   ...
    *   In the case that the file loaded is not a corefile, this simulates the 
    *   dyld initialization routines.
    """
    is_default = True # Tell CLE to automatically consider using the MachO backend
    _header = None

    def __init__(self, binary, target_arch=None, **kwargs):
        l.warning('The Mach-O backend is not well-supported. Good luck!')

        super(MachO, self).__init__(binary, **kwargs)

        parsed_macho = MachOLoader.MachO(self.binary)

        if not self.is_main_bin:
            # target_arch prefrence goes to main bin...
            target_arch = self.loader.main_object.arch.name.lower()

        if not target_arch is None:
            self._header = self.match_target_arch_to_header(target_arch, parsed_macho.headers)
            if not self._header:
                # Print out all architectures found?
                raise CLEError("Couldn't find architecture %s" % target_arch)
        else:
            if len(parsed_macho.headers) > 1:
                l.warning('No target slice specified. Picking one at random.. Good luck!')
            self._header = parsed_macho.headers[0]

        arch_ident = self.get_arch_from_header(self._header.header)
        # TODO: add lsb/msb support here properly. self._header.endian is exactly it
        self.set_arch(archinfo.arch_from_id(arch_ident, endness="lsb"))
        self.struct_byteorder = self._header.endian
                
        # XXX: Actually populate this...
        self.pic = True  # position independent executable?
        self.flags = None  # binary flags
        self.imported_libraries = ["Self"]  # ordinal 0 = SELF_LIBRARY_ORDINAL

        # XXX: Fill this in. 
        # This was what was historically done: self.sections_by_ordinal.extend(seg.sections)
        self.sections_by_ordinal = [None] # ordinal 0 = None == Self

        self.exports_by_name = {}  # note exports is currently a raw and unprocessed datastructure.
        # If we intend to use it we must first upgrade it to a class or somesuch
        self.entryoff = None
        self.unixthread_pc = None
        self.os = "Darwin"
        
        self.export_blob = None  # exports trie
        self.binding_blob = None  # binding information
        self.lazy_binding_blob = None  # lazy binding information
        self.weak_binding_blob = None  # weak binidng information
        self.symtab_offset = None # offset to the symtab
        self.symtab_nsyms = None # number of symbols in the symtab
        self.binding_done = False # if true binding was already done and do_bind will be a no-op

        # Library dependencies.
        self.linking = 'dynamic' # static is impossible in macos... kinda 

        # For some analysis the insertion order of the symbols is relevant and needs to be kept.
        # This is has to be separate from self.symbols because the latter is sorted by address
        self._ordered_symbols = []

        self.segments = []

        if self.is_main_bin:
            self.linked_base = 0x0100000000 

        # File is read, begin populating internal fields
        self._parse_load_cmds()
        #self._parse_exports()
        #self._parse_symbols(binary_file)
        #self._parse_mod_funcs()

    def _handle_segment_load_command(self, macholib_seginfo, macholib_secinfo):
        seg = MachOSegment(macholib_seginfo, macholib_secinfo) # load_cmd_trie[1] is the segment, load_cmd_trie[2] is the sections
        self.segments.append(seg)
        # Can't map here; need to determine linked_base before trying to map :(
        self.sections_by_ordinal.extend(seg.sections)

    def _map_segments(self):
        for seg in self.segments:
            if seg.segname == '__PAGEZERO':
                continue
            blob = self._read(self.binary_stream, self._header.offset + seg.offset, seg.filesize)
            if seg.filesize < seg.memsize:
                blob += b'\0' * (seg.memsize - seg.filesize)  # padding

            self.memory.add_backer(seg.vaddr - self.linked_base, blob)

    def _handle_main_load_command(self, entry_point_command):
        # What do I do with stacksize? :x
        self._entry = self.linked_base + entry_point_command.entryoff

    def _handle_dyld_info_command(self, dyld_info_cmd):
        """
        Extracts information blobs for rebasing, binding and export
        """
        f = self.binary_stream

        def blob_or_None(f,off,size): # helper
            return self._read(f,off,size) if off != 0 and size != 0 else None

        # Extract data blobs
        self.rebase_blob = blob_or_None(f, dyld_info_cmd.rebase_off, dyld_info_cmd.rebase_size)
        self.binding_blob = blob_or_None(f, dyld_info_cmd.bind_off, dyld_info_cmd.bind_size)
        self.weak_binding_blob = blob_or_None(f, dyld_info_cmd.weak_bind_off, dyld_info_cmd.weak_bind_size)
        self.lazy_binding_blob = blob_or_None(f, dyld_info_cmd.lazy_bind_off, dyld_info_cmd.lazy_bind_size)
        self.export_blob = blob_or_None(f, dyld_info_cmd.export_off, dyld_info_cmd.export_size)
        self._parse_exports()
        pass

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


    def _parse_load_cmds(self):
        has_symbol_table = False

        unhandled_load_cmds = set()
        
        for load_cmd_trie in self._header.commands:
            cmd = load_cmd_trie[0]
            cmd_name = cmd.get_cmd_name()
            if cmd_name == 'LC_SEGMENT' or cmd_name == 'LC_SEGMENT_64':
                self._handle_segment_load_command(load_cmd_trie[1], load_cmd_trie[2])
            elif cmd_name == 'LC_MAIN':
                self._handle_main_load_command(load_cmd_trie[1])
            elif cmd_name == 'LC_FUNCTION_STARTS':
                # Should use this unless user explicitly turns off
                pass
            elif cmd_name == 'LC_SYMTAB':
                has_symbol_table = True
            elif cmd_name == 'LC_LOAD_DYLINKER':
                self.deps.append(load_cmd_trie[2].decode().strip('\x00'))
            elif cmd_name == 'LC_LOAD_DYLIB':
                self.deps.append(load_cmd_trie[2].decode().strip('\x00'))
            elif cmd_name == 'LC_DYLD_INFO' or cmd_name == 'LC_DYLD_INFO_ONLY':
                # These two commands are handled identically in the dyld src code.
                self._handle_dyld_info_command(load_cmd_trie[1])
            elif cmd_name == 'LC_THREAD': # core file
                l.error("Core file support not currently implemented.")
            else:
                unhandled_load_cmds.add(cmd_name)
                pass

        try:
            l.warning("Not currently handling the following load commands: %s" % ", ".join(unhandled_load_cmds))
        except:
            # .get_cmd_name() returns the integer value of the cmd when it doesn't have a string name for it
            l.warning("It appears macholib doesn't know about one or more load commands in this macho.")
            l.warning(unhandled_load_cmds)

        seg_addrs = (x.vaddr for x in self.segments if x.segname != '__PAGEZERO')
        self.linked_base = min(seg_addrs)

        self._map_segments()

        if has_symbol_table:
            self._load_symbol_table()

    def _load_symbol_table(self):
        stable = MachOLoaderSymbolTable.SymbolTable(self._header.parent)

        # Parse out stable.extdefsyms
        for esym in stable.extdefsyms:
            sym = esym[0]
            sym_str = esym[1] # No need to decode, apparently :-)
            s = SymbolTableSymbol(self, sym_str, sym.n_type, sym.n_sect, sym.n_desc, sym.n_value - self.linked_base) 
            self.symbols.add(s)

        # Parse out stable.undefsyms
        for usym in stable.undefsyms:
            sym = usym[0]
            sym_str = usym[1]
            s = SymbolTableSymbol(self, sym_str, sym.n_type, sym.n_sect, sym.n_desc, sym.n_value - self.linked_base) 
            self.symbols.add(s)

        for lsym in stable.localsyms:
            sym = lsym[0]
            sym_str = lsym[1]
            s = SymbolTableSymbol(self, sym_str, sym.n_type, sym.n_sect, sym.n_desc, sym.n_value - self.linked_base) 
            self.symbols.add(s)

    # XXX: Should this be case insensitive?
    def get_arch_from_header(self, header):
        arch_lookup = {
            # contains all supported architectures. Note that apple deviates from standard ABI, see Apple docs
            # XXX: these are referred to differently in mach/machine.h
            0x100000c: "aarch64", # arm64
            0xc: "arm",
            0x7: "x86",
            0x1000007: "amd64", # x64, amd64
        }
        return arch_lookup[header.cputype]

    def match_target_arch_to_header(self, target_arch, headers):
        for mach_header in headers:
            if self.get_arch_from_header(mach_header.header) == target_arch:
                return mach_header
        return None

    @classmethod
    def check_compatibility(cls, spec, obj):
        with stream_or_path(spec) as stream:
            return cls.is_compatible(stream)
        return False

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x5)
        stream.seek(0)
        if identstring.startswith(struct.pack('I', MachOLoader.MH_MAGIC_64)) or \
           identstring.startswith(struct.pack('I', MachOLoader.MH_CIGAM_64)) or \
           identstring.startswith(struct.pack('I', MachOLoader.MH_MAGIC)) or \
           identstring.startswith(struct.pack('I', MachOLoader.MH_CIGAM)) or \
           identstring.startswith(struct.pack('>I', MachOLoader.FAT_MAGIC_64)) or \
           identstring.startswith(struct.pack('>I', MachOLoader.FAT_MAGIC)):
           # Being that Macholib doesn't have FAT_CIGAM.. I'm gonna assume it doesnt happen
            return True

        return False

    @property
    def initializers(self):
        # Parse __mod_init_func if exists
        return []

    @property
    def finalizers(self):
        # Parse __mod_term_func if exists (Or __mod_exit_func?)
        return []

    #def is_thumb_interworking(self, address):
    #    """Returns true if the given address is a THUMB interworking address"""
    #    # Note: Untested
    #    return self.arch.bits != 64 and address & 1

    #def decode_thumb_interworking(self, address):
    #    """Decodes a thumb interworking address"""
    #    # Note: Untested
    #    return address & ~1 if self.is_thumb_interworking(address) else address

    #def _parse_mod_funcs(self):
    #    l.debug("Parsing module init/term function pointers")

    #    fmt = "Q" if self.arch.bits == 64 else "I"
    #    size = 8 if self.arch.bits == 64 else 4

    #    # factoring out common code
    #    def parse_mod_funcs_internal(s, target):
    #        for i in range(s.vaddr, s.vaddr + s.memsize, size):
    #            addr = self._unpack_with_byteorder(fmt, self.memory.load(i, size))[0]
    #            l.debug("Addr: %#x", addr)
    #            target.append(addr)

    #    for seg in self.segments:
    #        for sec in seg.sections:

    #            if sec.type == 0x9:  # S_MOD_INIT_FUNC_POINTERS
    #                l.debug("Section %s contains init pointers", sec.sectname)
    #                parse_mod_funcs_internal(sec, self.mod_init_func_pointers)
    #            elif sec.type == 0xa:  # S_MOD_TERM_FUNC_POINTERS
    #                l.debug("Section %s contains term pointers", sec.sectname)
    #                parse_mod_funcs_internal(sec, self.mod_term_func_pointers)

    #    l.debug("Done parsing module init/term function pointers")

    def find_segment_by_name(self, name):
        for s in self.segments:
            if s.segname == name:
                return s
        return None

    @staticmethod
    def _read(fp, offset, size):
        """
        Simple read abstraction, reads size bytes from offset in file
        :param offset: Offset to seek() to
        :param size: number of bytes to be read
        :return: string of bytes or "" for EOF
        """
        fp.seek(offset)
        return fp.read(size)

    #def _unpack_with_byteorder(self, fmt, data):
    #    """
    #    Appends self.struct_byteorder before fmt to ensure usage of correct byteorder
    #    :return: struct.unpack(self.struct_byteorder+fmt,input)
    #    """
    #    return struct.unpack(self.struct_byteorder + fmt, data)

    #def _unpack(self, fmt, fp, offset, size):
    #    """Convenience"""
    #    return self._unpack_with_byteorder(fmt, self._read(fp, offset, size))

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
