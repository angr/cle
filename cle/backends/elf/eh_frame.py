"""
A minimal .eh_frame walker that extracts the initial location and address range of every FDE without decoding call
frame instructions. pyelftools decodes every CFI instruction, which is too slow to run on every loaded ELF object.
"""

from __future__ import annotations

import struct

DW_EH_PE_absptr = 0x00
DW_EH_PE_uleb128 = 0x01
DW_EH_PE_udata2 = 0x02
DW_EH_PE_udata4 = 0x03
DW_EH_PE_udata8 = 0x04
DW_EH_PE_sleb128 = 0x09
DW_EH_PE_sdata2 = 0x0A
DW_EH_PE_sdata4 = 0x0B
DW_EH_PE_sdata8 = 0x0C
DW_EH_PE_pcrel = 0x10
DW_EH_PE_datarel = 0x30
DW_EH_PE_omit = 0xFF

_FIXED_FORMATS = {
    DW_EH_PE_udata2: "H",
    DW_EH_PE_udata4: "I",
    DW_EH_PE_udata8: "Q",
    DW_EH_PE_sdata2: "h",
    DW_EH_PE_sdata4: "i",
    DW_EH_PE_sdata8: "q",
}


class EhFrameParseError(Exception):
    """
    Raised when .eh_frame contains something this parser does not support. Callers should fall back to pyelftools.
    """


class _Reader:
    __slots__ = ("data", "pos", "endian")

    def __init__(self, data: bytes, endian: str):
        self.data = data
        self.pos = 0
        self.endian = endian

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def fixed(self, fmt: str) -> int:
        size = struct.calcsize(fmt)
        (v,) = struct.unpack_from(self.endian + fmt, self.data, self.pos)
        self.pos += size
        return v

    def uleb(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return result

    def sleb(self) -> int:
        result = 0
        shift = 0
        while True:
            b = self.u8()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                if b & 0x40:
                    result -= 1 << shift
                return result

    def cstr(self) -> bytes:
        end = self.data.index(b"\x00", self.pos)
        s = self.data[self.pos : end]
        self.pos = end + 1
        return s

    def _value(self, fmt: int, ptr_size: int) -> int:
        if fmt == DW_EH_PE_absptr:
            value = self.fixed("Q" if ptr_size == 8 else "I")
        elif fmt == DW_EH_PE_uleb128:
            value = self.uleb()
        elif fmt == DW_EH_PE_sleb128:
            value = self.sleb()
        elif fmt in _FIXED_FORMATS:
            value = self.fixed(_FIXED_FORMATS[fmt])
        else:
            raise EhFrameParseError(f"unsupported pointer format {fmt:#x}")
        return value

    def skip_encoded(self, encoding: int, ptr_size: int) -> None:
        """
        Consume a DW_EH_PE-encoded pointer whose value is not needed (e.g. the personality routine).
        """
        if encoding != DW_EH_PE_omit:
            self._value(encoding & 0x0F, ptr_size)

    def encoded(self, encoding: int, section_addr: int, ptr_size: int) -> int:
        """
        Read a DW_EH_PE-encoded pointer. Only the application modes GCC emits for pc_begin are supported.
        """
        if encoding == DW_EH_PE_omit:
            raise EhFrameParseError("omitted pointer")
        if encoding & 0x80:
            raise EhFrameParseError("indirect pointer encoding")
        field_addr = section_addr + self.pos
        value = self._value(encoding & 0x0F, ptr_size)
        application = encoding & 0x70
        if application == 0:
            return value
        if application == DW_EH_PE_pcrel:
            return (field_addr + value) & ((1 << (ptr_size * 8)) - 1)
        raise EhFrameParseError(f"unsupported pointer application {application:#x}")


def parse_fde_ranges(data: bytes, section_addr: int, ptr_size: int, little_endian: bool) -> list[tuple[int, int]]:
    """
    Walk an .eh_frame section and return (initial_location, address_range) for every FDE.

    :param data:            Raw bytes of the .eh_frame section.
    :param section_addr:    Link-time virtual address of the section (needed for pc-relative pointers).
    :param ptr_size:        Size of a native pointer in bytes.
    :param little_endian:   Endianness of the object.
    :raises EhFrameParseError: On any encoding this parser does not handle.
    """
    endian = "<" if little_endian else ">"
    r = _Reader(data, endian)
    # CIE offset -> pointer encoding of the FDEs that reference it
    cie_encodings: dict[int, int] = {}
    fdes: list[tuple[int, int]] = []

    try:
        while r.pos + 4 <= len(data):
            entry_start = r.pos
            length = r.fixed("I")
            if length == 0:
                # a zero terminator; linked objects may carry several of them, so keep walking
                continue
            if length == 0xFFFFFFFF:
                length = r.fixed("Q")
            body_start = r.pos
            entry_end = body_start + length
            if entry_end > len(data):
                raise EhFrameParseError("entry runs past the end of the section")
            cie_id = r.fixed("I")
            if cie_id == 0:
                version = r.u8()
                augmentation = r.cstr()
                if b"eh" in augmentation:
                    r.pos += ptr_size
                r.uleb()  # code alignment factor
                r.sleb()  # data alignment factor
                if version == 1:
                    r.u8()  # return address register
                else:
                    r.uleb()
                encoding = DW_EH_PE_absptr
                if augmentation.startswith(b"z"):
                    r.uleb()  # augmentation data length
                    for ch in augmentation[1:]:
                        if ch == ord("L"):
                            r.u8()
                        elif ch == ord("P"):
                            r.skip_encoded(r.u8(), ptr_size)
                        elif ch == ord("R"):
                            encoding = r.u8()
                        elif ch in (ord("S"), ord("B"), ord("G")):
                            pass
                        else:
                            raise EhFrameParseError(f"unknown augmentation {augmentation!r}")
                cie_encodings[entry_start] = encoding
            else:
                cie_offset = body_start - cie_id
                if cie_offset not in cie_encodings:
                    raise EhFrameParseError("FDE references an unknown CIE")
                encoding = cie_encodings[cie_offset]
                pc_begin = r.encoded(encoding, section_addr, ptr_size)
                # the range is always encoded with the value format only, never pc-relative
                pc_range = r.encoded(encoding & 0x0F, section_addr, ptr_size)
                fdes.append((pc_begin, pc_range))
            r.pos = entry_end
    except (struct.error, IndexError, ValueError) as ex:
        raise EhFrameParseError(str(ex)) from ex

    return fdes
