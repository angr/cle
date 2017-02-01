# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).

from ...errors import CLECompatibilityError, CLEInvalidBinaryError
import logging, struct

l = logging.getLogger('cle.MachO.binding')

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


def read_uleb(blob, offset):
    """Reads a number encoded as uleb128"""
    result = 0
    shift = 0
    index = offset
    end = len(blob)
    done = False
    while not done and index < end:
        b = struct.unpack("B", blob[index])[0]
        result |= ((b & 0x7f) << shift)
        shift += 7
        index += 1
        if b & 0x80 == 0:
            done = True

    return (result, index - offset)


def read_sleb(blob, offset):
    """Reads a number encoded as sleb128"""
    result = 0
    shift = 0
    index = offset
    end = len(blob)
    done = False
    while not done and index < end:
        b = struct.unpack("B", blob[index])[0]
        result |= ((b & 0x7f) << shift)
        shift += 7
        index += 1
        if b & 0x80 == 0:
            done = True

    if b & 0x40:
        # two's complement
        result -= (1 << shift)

    return (result, index - offset)


class BindingState(object):
    """State object"""

    def __init__(s, is_64):
        s.index = 0
        s.done = False
        s.lib_ord = 0
        s.sym_name = ""
        s.sym_flags = 0
        s.binding_type = 0
        s.addend = 0
        s.segment_index = 0
        s.address = 0
        s.seg_end_address = 0  # TODO: no rebasing support
        s.wraparound = 2 ** 64  # address is expected to properly overflow and address is uintptr_t (unsigned long according to _uintptr_t.h)
        s.sizeof_intptr_t = 8 if is_64 else 4  # experimentally determined
        s.bind_handler = None  # function(state,binary) => None

    def add_address_ov(s, address, addend):
        """ this is a very ugly klugde. It is needed because dyld relies on overflow
            semantics and represents several negative offsets through BIG ulebs"""
        tmp = address + addend
        if tmp > s.wraparound:
            tmp -= s.wraparound
        s.address = tmp

    def check_address_bounds(self):
        if self.address >= self.seg_end_address:
            l.error(
                "address >= seg_end_address (0x{1:X}>=0x{2:X})".format(self.index, self.address, self.seg_end_address))
            raise CLEInvalidBinaryError()


class BindingHelper(object):
    """Factors out binding logic from MachO.
    Intended to work in close conjunction with MachO not for standalone use"""

    def __init__(self, binary):
        self.binary = binary

    def do_normal_bind(self, blob):
        """Performs non-lazy, non-weak bindings
        :param blob: Blob containing binding opcodes"""

        if blob is None:
            return  # skip

        l.debug("Binding non-lazy, non-weak symbols")
        s = BindingState(self.binary.is_64bit)
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

        s = BindingState(self.binary.is_64bit)
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

    def _do_bind_generic(self, blob, init_state, opcode_dict):
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
            l.debug("Current address: 0x{0:X}, blob index (offset): 0x{1:X}".format(s.address, s.index))
            raw_opcode = struct.unpack("B", blob[s.index])[0]
            opcode = raw_opcode & OPCODE_MASK
            immediate = raw_opcode & IMM_MASK
            s.index += 1
            try:
                h = opcode_dict[opcode]
                s = h(s, self.binary, immediate, blob)
            except KeyError:
                l.error("Invalid opcode for current binding: 0x{0:X}".format(opcode))

        return s


# The following functions realize different variants of handling binding opcodes
# the format is def X(state,binary,immediate,blob) => state
def n_opcode_done(s, b, i, blob):
    l.debug("BIND_OPCODE_DONE @ 0x{0:X}".format(s.index))
    s.done = True
    return s


def n_opcode_set_dylib_ordinal_imm(s, b, i, blob):
    l.debug("SET_DYLIB_ORDINAL_IMM @ 0x{0:X}: {1}".format(s.index, i))
    s.lib_ord = i
    return s


def n_opcode_set_dylib_ordinal_uleb(s, b, i, blob):
    uleb = read_uleb(blob, s.index)
    s.lib_ord = uleb[0]
    s.index += uleb[1]
    l.debug("SET_DYLIB_ORDINAL_ULEB @ 0x{0:X}: {1}".format(s.index, s.lib_ord))
    return s


def n_opcode_set_dylib_special_imm(s, b, i, blob):
    if i == 0:
        s.lib_ord = 0
    else:
        s.lib_ord = (i | OPCODE_MASK) - 256
    l.debug("SET_DYLIB_SPECIAL_IMM @ 0x{0:X}: {1}".format(s.index, s.lib_ord))
    return s


def n_opcode_set_trailing_flags_imm(s, b, i, blob):
    s.sym_name = ""
    s.sym_flags = i
    while blob[s.index] != "\x00":
        s.sym_name += blob[s.index]
        s.index += 1
    s.index += 1  # move past 0 byte
    l.debug("SET_SYMBOL_TRAILING_FLAGS_IMM @ 0x{0:X}: '{1}',0x{2:X}".format(s.index - len(s.sym_name) - 1, s.sym_name,
                                                                            s.sym_flags))
    return s


def n_opcode_set_type_imm(s, b, i, blob):
    s.binding_type = i
    l.debug("SET_TYPE_IMM @ 0x{0:X}: {1}".format(s.index, s.binding_type))
    return s


def n_opcode_set_addend_sleb(s, b, i, blob):
    sleb = read_sleb(blob, s.index)
    s.addend = sleb[0]
    l.debug("SET_ADDEND_SLEB @ 0x{0:X}: {1}".format(s.index, s.addend))
    s.index += sleb[1]
    return s


def n_opcode_set_segment_and_offset_uleb(s, b, i, blob):
    s.segment_index = i
    uleb = read_uleb(blob, s.index)
    l.debug("(n)SET_SEGMENT_AND_OFFSET_ULEB @ 0x{0:X}: {1}, {2}".format(s.index, s.segment_index, uleb[0]))
    s.index += uleb[1]
    seg = b.segments[s.segment_index]
    s.add_address_ov(seg.vaddr, uleb[0])
    s.seg_end_address = seg.vaddr + seg.memsize

    return s


def l_opcode_set_segment_and_offset_uleb(s, b, i, blob):
    uleb = read_uleb(blob, s.index)
    l.debug("(l)SET_SEGMENT_AND_OFFSET_ULEB @ 0x{0:X}: {1}, {2}".format(s.index, i, uleb[0]))
    seg = b.segments[i]
    s.add_address_ov(seg.vaddr, uleb[0])
    s.index += uleb[1]
    return s


def n_opcode_add_addr_uleb(s, b, i, blob):
    uleb = read_uleb(blob, s.index)
    s.add_address_ov(s.address, uleb[0])
    l.debug("ADD_ADDR_ULEB @ 0x{0:X}: {1}".format(s.index, uleb[0]))
    s.index += uleb[1]
    return s


def n_opcode_do_bind(s, b, i, blob):
    l.debug("(n)DO_BIND @ 0x{0:X}".format(s.index))
    s.check_address_bounds()
    s.bind_handler(s, b)
    s.add_address_ov(s.address, s.sizeof_intptr_t)
    return s


def l_opcode_do_bind(s, b, i, blob):
    l.debug("(l)DO_BIND @ 0x{0:X}".format(s.index))
    s.bind_handler(s, b)
    return s


def n_opcode_do_bind_add_addr_uleb(s, b, i, blob):
    uleb = read_uleb(blob, s.index)
    l.debug("DO_BIND_ADD_ADDR_ULEB @ 0x{0:X}: {0}".format(s.index, uleb[0]))
    if s.address >= s.seg_end_address:
        l.error(
            "DO_BIND_ADD_ADDR_ULEB @ 0x{0:X}: address >= seg_end_address (0x{1:X}>=0x{2:X})".format(s.index, s.address,
                                                                                                    s.seg_end_address))
        raise CLEInvalidBinaryError()
    s.index += uleb[1]
    s.bind_handler(s, b)
    # this is done AFTER binding in preparation for the NEXT step
    s.add_address_ov(s.address, uleb[0] + s.sizeof_intptr_t)
    return s


def n_opcode_do_bind_add_addr_imm_scaled(s, b, i, blob):
    l.debug("DO_BIND_ADD_ADDR_IMM_SCALED @ 0x{0:X}: {1}".format(s.index, i))
    if s.address >= s.seg_end_address:
        l.error("DO_BIND_ADD_ADDR_IMM_SCALED @ 0x{0:X}: address >= seg_end_address (0x{1:X}>=0x{2:X})".format(s.index,
                                                                                                              s.address,
                                                                                                              s.seg_end_address))
        raise CLEInvalidBinaryError()
    s.bind_handler(s, b)
    # this is done AFTER binding in preparation for the NEXT step
    s.add_address_ov(s.address, (i * s.sizeof_intptr_t) + s.sizeof_intptr_t)
    return s


def n_opcode_do_bind_uleb_times_skipping_uleb(s, b, i, blob):
    count = read_uleb(blob, s.index)
    s.index += count[1]
    skip = read_uleb(blob, s.index)
    s.index += skip[1]
    l.debug(
        "DO_BIND_ULEB_TIMES_SKIPPING_ULEB @ 0x{0:X}: {1},{2}".format(s.index - skip[1] - count[1], count[0], skip[0]))
    for i in range(0, count[0]):
        if s.address >= s.seg_end_address:
            l.error("DO_BIND_ADD_ADDR_IMM_SCALED @ 0x{0:X}: address >= seg_end_address (0x{1:X}>=0x{2:X})".format(
                s.index - skip[1] - count[1], s.address, s.seg_end_address))
            raise CLEInvalidBinaryError()
        s.bind_handler(s, b)
        s.add_address_ov(s.address, skip[0] + s.sizeof_intptr_t)
    return s


# default binding handler
def default_binding_handler(state, binary):
    """Binds location to the symbol with the given name and library ordinal
    """

    # locate the symbol:
    # TODO: A lookup structure of some kind would be nice (see __init__)
    matches = [s for s in binary.symbols if s.name == state.sym_name and s.library_ordinal == state.lib_ord]
    if len(matches) > 1:
        l.error("Cannot bind: More than one match for ('{0}',{1})".format(state.sym_name, state.lib_ord))
        raise CLEInvalidBinaryError()
    elif len(matches) < 1:
        l.error("Cannot bind: No match for ('{0}',{1})".format(state.sym_name, state.lib_ord))
        raise CLEInvalidBinaryError()

    symbol = matches[0]
    location = state.address

    value = symbol.addr + state.addend
    if state.binding_type == 1:  # POINTER
        l.info("Updating address 0x{1:X} with symobl '{0}' @ 0x{2:X}".format(state.sym_name, location, value))
        binary.memory.write_bytes(location,
                                  struct.pack(binary.struct_byteorder + ("Q" if binary.is_64bit else "I"), value))
        symbol.bind_xrefs.append(location)
    elif state.binding_type == 2:  # ABSOLUTE32
        location_32 = location % (2 ** 32)
        value_32 = value % (2 ** 32)
        l.info("Updating address 0x{1:X} with symobl '{0}' @ 0x{2:X}".format(state.sym_name, location_32, value_32))
        binary.memory.write_bytes(location_32, struct.pack(binary.struct_byteorder + "I", value_32))
        symbol.bind_xrefs.append(location_32)
    elif state.binding_type == 3:  # PCREL32
        location_32 = location % (2 ** 32)
        value_32 = (value - (location + 4)) % (2 ** 32)
        l.info("Updating address 0x{1:X} with symobl '{0}' @ 0x{2:X}".format(state.sym_name, location_32, value_32))
        binary.memory.write_bytes(location_32, struct.pack(binary.struct_byteorder + "I", value_32))
        symbol.bind_xrefs.append(location_32)
    else:
        l.error("Unknown BIND_TYPE: {0}".format(type))
        raise CLEInvalidBinaryError()
