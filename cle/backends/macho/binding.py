# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/) and updated in September 2019.

import struct
from typing import Callable, Dict, Tuple, TYPE_CHECKING
import logging


from ..relocation import Relocation
from .. import Backend

from .symbol import BindingSymbol, AbstractMachOSymbol, SymbolTableSymbol, DyldBoundSymbol




from ...errors import CLEInvalidBinaryError
from ...address_translator import AT

if TYPE_CHECKING:
    from ... import MachO

l = logging.getLogger(name=__name__)

OPCODE_MASK = 0xF0
IMM_MASK = 0x0F
BIND_TYPE_POINTER = 1
BIND_TYPE_TEXT_ABSOLUTE32 = 2
BIND_TYPE_TEXT_PCREL32 = 3
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0

if bytes is not str:
    chh = lambda x: x
else:
    chh = ord


def read_uleb(blob: bytes, offset: int) -> Tuple[int, int]:
    """Reads a number encoded as uleb128"""
    result = 0
    shift = 0
    index = offset

    while index < len(blob):
        b = chh(blob[index])
        result |= ((b & 0x7f) << shift)
        shift += 7
        index += 1
        if b & 0x80 == 0:
            break

    return result, index - offset


def read_sleb(blob, offset):
    """Reads a number encoded as sleb128"""
    result = 0
    shift = 0
    index = offset

    while index < len(blob):
        b = chh(blob[index])
        result |= ((b & 0x7f) << shift)
        shift += 7
        index += 1
        if b & 0x80 == 0:
            if b & 0x40:
                # two's complement
                result -= (1 << shift)
            break

    return result, index - offset


class BindingState():
    """State object"""

    def __init__(self, is_64):
        self.index = 0
        self.done = False
        self.lib_ord = 0
        self.sym_name = ""
        self.sym_flags = 0
        self.binding_type = 0
        self.addend = 0
        self.segment_index = 0
        self.address = 0
        self.seg_end_address = 0  # TODO: no rebasing support
        # address is expected to properly overflow and address is uintptr_t (unsigned long according to _uintptr_t.h)
        self.wraparound = 2 ** 64
        self.sizeof_intptr_t = 8 if is_64 else 4  # experimentally determined
        self.bind_handler = None  # function(state,binary) => None

    def add_address_ov(self, address, addend):
        """ this is a very ugly klugde. It is needed because dyld relies on overflow
            semantics and represents several negative offsets through BIG ulebs"""
        tmp = address + addend
        if tmp > self.wraparound:
            tmp -= self.wraparound
        self.address = tmp

    def check_address_bounds(self):
        if self.address >= self.seg_end_address:
            l.error("index %d: address >= seg_end_address (%#x >= %#x)", self.index, self.address, self.seg_end_address)
            raise CLEInvalidBinaryError()


class BindingHelper():
    """Factors out binding logic from MachO.
    Intended to work in close conjunction with MachO not for standalone use"""
    binary: 'MachO'

    def __init__(self, binary):
        self.binary = binary

    def do_normal_bind(self, blob: bytes):
        """Performs non-lazy, non-weak bindings
        :param blob: Blob containing binding opcodes"""

        if blob is None:
            return  # skip

        l.debug("Binding non-lazy, non-weak symbols")
        s = BindingState(self.binary.arch.bits == 64)
        seg = self.binary.segments[0]
        s.seg_end_address = seg.vaddr + seg.memsize
        s.bind_handler = default_binding_handler
        self._do_bind_generic(blob, s, {
            0: n_opcode_done,
            0x10: n_opcode_set_dylib_ordinal_imm,
            0x20: n_opcode_set_dylib_ordinal_uleb,
            0x30: n_opcode_set_dylib_special_imm,
            0x40: n_opcode_set_trailing_flags_imm,
            0x50: n_opcode_set_type_imm,
            0x60: n_opcode_set_addend_sleb,
            0x70: n_opcode_set_segment_and_offset_uleb,
            0x80: n_opcode_add_addr_uleb,
            0x90: n_opcode_do_bind,
            0xA0: n_opcode_do_bind_add_addr_uleb,
            0xB0: n_opcode_do_bind_add_addr_imm_scaled,
            0xC0: n_opcode_do_bind_uleb_times_skipping_uleb
        })

        l.debug("Done binding non-lazy, non-weak symbols ")

    def do_lazy_bind(self, blob):
        """
        Performs lazy binding
        """
        if blob is None:
            return  # skip
        l.debug("Binding lazy symbols")

        s = BindingState(self.binary.arch.bits == 64)
        s.index = 0
        s.bind_handler = default_binding_handler
        end = len(blob)
        # We need to iterate the iteration as every lazy binding entry ends with BIND_OPCODE_DONE
        while s.index < end:
            # re-initialise state (except index)
            s.binding_type = 1
            s.address = 0
            s.sym_name = ""
            s.sym_flags = 0
            s.lib_ord = 0
            s.done = False
            s.addend = 0
            s.segment_index = 0
            s.seg_end_address = 0  # TODO: no rebasing support

            self._do_bind_generic(blob, s, {
                0x00: n_opcode_done,
                0x10: n_opcode_set_dylib_ordinal_imm,
                0x20: n_opcode_set_dylib_ordinal_uleb,
                0x30: n_opcode_set_dylib_special_imm,
                0x40: n_opcode_set_trailing_flags_imm,
                0x50: n_opcode_set_type_imm,
                0x70: l_opcode_set_segment_and_offset_uleb,
                0x90: l_opcode_do_bind,
            })

        l.debug("Done binding lazy symbols")

    def _do_bind_generic(self,
                         blob,
                         init_state: BindingState,
                         opcode_dict: Dict[int,
                                           Callable[[BindingState, 'MachO', int, bytes], BindingState]]
                         ):
        """
        Does the actual binding work. Represents a generic framework for interpreting binding opcodes
        :param blob: blob of binding opcodes
        :param init_state: Initial BindingState
        :param opcode_dict: Dictionary opcode=> handler
        :return: resulting binding state
        """
        s = init_state
        seg = self.binary.segments[s.segment_index]
        s.seg_end_address = seg.vaddr + seg.memsize  # TODO: no rebasing support
        end = len(blob)
        while not s.done and s.index < end:
            l.debug("Current address: %#x, blob index (offset): %#x", s.address, s.index)
            raw_opcode = blob[s.index]
            opcode = raw_opcode & OPCODE_MASK
            immediate = raw_opcode & IMM_MASK
            s.index += 1
            try:
                h = opcode_dict[opcode]
                s = h(s, self.binary, immediate, blob)
            except KeyError:
                l.error("Invalid opcode for current binding: %#x", opcode)

        return s


# pylint: disable=unused-argument
# The following functions realize different variants of handling binding opcodes
# the format is def X(state,binary,immediate,blob) => state
def n_opcode_done(s: BindingState, _b: 'MachO', _i: int, _blob: bytes) -> BindingState:
    l.debug("BIND_OPCODE_DONE @ %#x", s.index)
    s.done = True
    return s


def n_opcode_set_dylib_ordinal_imm(s: BindingState, _b: 'MachO', i: int, _blob: bytes) -> BindingState:
    l.debug("SET_DYLIB_ORDINAL_IMM @ %#x: %d", s.index, i)
    s.lib_ord = i
    return s


def n_opcode_set_dylib_ordinal_uleb(s: BindingState, _b: 'MachO', _i: int, blob: bytes) -> BindingState:
    uleb = read_uleb(blob, s.index)
    s.lib_ord = uleb[0]
    s.index += uleb[1]
    l.debug("SET_DYLIB_ORDINAL_ULEB @ %#x: %d", s.index, s.lib_ord)
    return s


def n_opcode_set_dylib_special_imm(s: BindingState, _b: 'MachO', i: int, _blob: bytes) -> BindingState:
    if i == 0:
        s.lib_ord = 0
    else:
        s.lib_ord = (i | OPCODE_MASK) - 256
    l.debug("SET_DYLIB_SPECIAL_IMM @ %#x: %d", s.index, s.lib_ord)
    return s


def n_opcode_set_trailing_flags_imm(s: BindingState, _b: 'MachO', i: int, blob: bytes) -> BindingState:
    s.sym_name = ""
    s.sym_flags = i

    while blob[s.index] != 0:
        s.sym_name += chr(blob[s.index])
        s.index += 1

    s.index += 1  # move past 0 byte
    l.debug("SET_SYMBOL_TRAILING_FLAGS_IMM @ %#x: %r,%#x", s.index - len(s.sym_name) - 1, s.sym_name, s.sym_flags)
    return s


def n_opcode_set_type_imm(s: BindingState, _b: 'MachO', i: int, _blob: bytes) -> BindingState:
    # pylint: disable=unused-argument
    s.binding_type = i
    l.debug("SET_TYPE_IMM @ %#x: %d", s.index, s.binding_type)
    return s


def n_opcode_set_addend_sleb(s: BindingState, _b: 'MachO', _i: int, blob: bytes) -> BindingState:
    sleb = read_sleb(blob, s.index)
    s.addend = sleb[0]
    l.debug("SET_ADDEND_SLEB @ %#x: %d", s.index, s.addend)
    s.index += sleb[1]
    return s


def n_opcode_set_segment_and_offset_uleb(s: BindingState, b: 'MachO', i: int, blob: bytes) -> BindingState:
    s.segment_index = i
    uleb = read_uleb(blob, s.index)
    l.debug("(n)SET_SEGMENT_AND_OFFSET_ULEB @ %#x: %d, %d", s.index, s.segment_index, uleb[0])
    s.index += uleb[1]
    seg = b.segments[s.segment_index]
    s.add_address_ov(seg.vaddr, uleb[0])
    s.seg_end_address = seg.vaddr + seg.memsize

    return s


def l_opcode_set_segment_and_offset_uleb(s: BindingState, b: 'MachO', i: int, blob: bytes) -> BindingState:
    uleb = read_uleb(blob, s.index)
    l.debug("(l)SET_SEGMENT_AND_OFFSET_ULEB @ %#x: %d, %d", s.index, i, uleb[0])
    seg = b.segments[i]
    s.add_address_ov(seg.vaddr, uleb[0])
    s.index += uleb[1]
    return s


def n_opcode_add_addr_uleb(s: BindingState, _b: 'MachO', _i: int, blob: bytes) -> BindingState:
    uleb = read_uleb(blob, s.index)
    s.add_address_ov(s.address, uleb[0])
    l.debug("ADD_ADDR_ULEB @ %#x: %d", s.index, uleb[0])
    s.index += uleb[1]
    return s


def n_opcode_do_bind(s: BindingState, b: 'MachO', _i: int, _blob: bytes) -> BindingState:
    l.debug("(n)DO_BIND @ %#x", s.index)
    s.check_address_bounds()
    s.bind_handler(s, b)
    s.add_address_ov(s.address, s.sizeof_intptr_t)
    return s


def l_opcode_do_bind(s: BindingState, b: 'MachO', _i: int, _blob: bytes) -> BindingState:
    l.debug("(l)DO_BIND @ %#x", s.index)
    s.bind_handler(s, b)
    return s


def n_opcode_do_bind_add_addr_uleb(s: BindingState, b: 'MachO', _i: int, blob: bytes) -> BindingState:
    uleb = read_uleb(blob, s.index)
    l.debug("DO_BIND_ADD_ADDR_ULEB @ %#x: %d", s.index, uleb[0])
    if s.address >= s.seg_end_address:
        l.error("DO_BIND_ADD_ADDR_ULEB @ %#x: address >= seg_end_address (%#x>=%#x)",
                s.index, s.address, s.seg_end_address)
        raise CLEInvalidBinaryError()
    s.index += uleb[1]
    s.bind_handler(s, b)
    # this is done AFTER binding in preparation for the NEXT step
    s.add_address_ov(s.address, uleb[0] + s.sizeof_intptr_t)
    return s


def n_opcode_do_bind_add_addr_imm_scaled(s: BindingState, b: 'MachO', i: int, _blob: bytes) -> BindingState:
    l.debug("DO_BIND_ADD_ADDR_IMM_SCALED @ %#x: %d", s.index, i)
    if s.address >= s.seg_end_address:
        l.error("DO_BIND_ADD_ADDR_IMM_SCALED @ %#x: address >= seg_end_address (%#x>=%#x)",
                s.index, s.address, s.seg_end_address)
        raise CLEInvalidBinaryError()
    s.bind_handler(s, b)
    # this is done AFTER binding in preparation for the NEXT step
    s.add_address_ov(s.address, (i * s.sizeof_intptr_t) + s.sizeof_intptr_t)
    return s


def n_opcode_do_bind_uleb_times_skipping_uleb(s: BindingState, b: 'MachO', _i: int, blob: bytes) -> BindingState:
    count = read_uleb(blob, s.index)
    s.index += count[1]
    skip = read_uleb(blob, s.index)
    s.index += skip[1]
    l.debug(
        "DO_BIND_ULEB_TIMES_SKIPPING_ULEB @ %#x: %d,%d", s.index - skip[1] - count[1], count[0], skip[0])
    for _ in range(0, count[0]):
        if s.address >= s.seg_end_address:
            l.error("DO_BIND_ADD_ADDR_IMM_SCALED @ %#x: address >= seg_end_address (%#x >= %#x)",
                    s.index - skip[1] - count[1], s.address, s.seg_end_address)
            raise CLEInvalidBinaryError()
        s.bind_handler(s, b)
        s.add_address_ov(s.address, skip[0] + s.sizeof_intptr_t)
    return s


class MachORelocation(Relocation):
    """
    Generic Relocation for MachO. For now it just deals with symbols
    """
    def __init__(self, owner: Backend, symbol: AbstractMachOSymbol, relative_addr: int, data):
        super().__init__(owner, symbol, relative_addr)
        self.data = data

    def resolve_symbol(self, solist, thumb=False, extern_object=None, **kwargs):
        if isinstance(self.symbol, (SymbolTableSymbol, BindingSymbol, DyldBoundSymbol)):
            if self.symbol.library_name in [so.binary_basename for so in solist]:
                raise NotImplementedError(
                    "Symbol could actually be resolved because we have the required library,"
                    " but that isn't implemented yet")
            else:
                # Create an extern symbol for it
                new_symbol = extern_object.make_extern(self.symbol.name, sym_type=self.symbol._type, thumb=thumb)
                self.resolve(new_symbol, extern_object=extern_object)
        else:
            raise NotImplementedError("Did not expect this to happen")

    @property
    def dest_addr(self):
        """
        mach-o rebasing is hard to handle, so this behaviour differs from other relocations
        """
        return self.rebased_addr


    @property
    def value(self):
        return self.resolvedby.rebased_addr

    def __repr__(self):
        return f"<MachO Reloc for {self.symbol} at {hex(self.relative_addr)}>"

# default binding handler
def default_binding_handler(state: BindingState, binary: 'MachO'):
    """Binds location to the symbol with the given name and library ordinal
    """

    # locate the symbol:
    matches = binary.symbols.get_by_name_and_ordinal(state.sym_name, state.lib_ord)
    if len(matches) > 1:
        l.error("Cannot bind: More than one match for (%r,%d)", state.sym_name, state.lib_ord)
        raise CLEInvalidBinaryError()
    if len(matches) < 1:
        l.info("No match for (%r,%d), generating BindingSymbol ...", state.sym_name, state.lib_ord)
        matches = [BindingSymbol(binary, state.sym_name, state.lib_ord)]
        binary.symbols.add(matches[0])
        binary._ordered_symbols.append(matches[0])

    symbol = matches[0]
    location = state.address

    # If the linked_addr is equal to zero, it's an imported symbol which is by that time unresolved.
    # Don't write addend's there

    value = symbol.linked_addr + state.addend if symbol.linked_addr != 0 else 0x0

    if state.binding_type == 1:  # POINTER
        l.debug("Updating address %#x with symobl %r @ %#x", location, state.sym_name, value)
        addr = AT.from_mva(location, binary).to_rva()
        data = struct.pack(binary.struct_byteorder + ("Q" if binary.arch.bits == 64 else "I"), value)
        reloc = MachORelocation(binary, symbol, addr, data)
        binary.relocs.append(reloc)
        symbol.bind_xrefs.append(location)
    elif state.binding_type == 2:  # ABSOLUTE32
        location_32 = location % (2 ** 32)
        value_32 = value % (2 ** 32)
        l.debug("Updating address %#x with symobl %r @ %#x", state.sym_name, location_32, value_32)
        binary.memory.store(
            AT.from_lva(location_32, binary).to_rva(),
            struct.pack(binary.struct_byteorder + "I", value_32))
        symbol.bind_xrefs.append(location_32)
    elif state.binding_type == 3:  # PCREL32
        location_32 = location % (2 ** 32)
        value_32 = (value - (location + 4)) % (2 ** 32)
        l.debug("Updating address %#x with symobl %r @ %#x", state.sym_name, location_32, value_32)
        binary.memory.store(
            AT.from_lva(location_32, binary).to_rva(),
            struct.pack(binary.struct_byteorder + "I", value_32))
        symbol.bind_xrefs.append(location_32)
    else:
        l.error("Unknown BIND_TYPE: %d", state.binding_type)
        raise CLEInvalidBinaryError()
