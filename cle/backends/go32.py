"""
Loader for DJGPP go32 executables: a DOS MZ stub followed by the i386 COFF executable it runs.
"""

from __future__ import annotations

import ctypes
import logging
import struct
from enum import IntFlag
from typing import BinaryIO

import archinfo

from cle.errors import CLEInvalidBinaryError

from .backend import Backend, register_backend
from .coff import IMAGE_FILE_MACHINE, IMAGE_SYM_CLASS, CoffFileHeader, CoffSectionTableEntry, CoffSymbolTableEntry
from .region import Section, Segment
from .symbol import Symbol, SymbolType

__all__ = ("Go32", "Go32Section", "coff_image_offset")

log = logging.getLogger(__name__)

_ZMAGIC = 0o413


class AoutHeader(ctypes.LittleEndianStructure):
    """
    The a.out optional header of a COFF executable
    """

    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [
        ("magic", ctypes.c_uint16),
        ("vstamp", ctypes.c_uint16),
        ("tsize", ctypes.c_uint32),
        ("dsize", ctypes.c_uint32),
        ("bsize", ctypes.c_uint32),
        ("entry", ctypes.c_uint32),
        ("text_start", ctypes.c_uint32),
        ("data_start", ctypes.c_uint32),
    ]


class STYP(IntFlag):
    """
    The section flags that say what a COFF executable section holds
    """

    TEXT = 0x20
    DATA = 0x40
    BSS = 0x80


def coff_image_offset(stream: BinaryIO) -> int | None:
    """
    Return the file offset of the COFF executable a go32 stub runs, or None if the stream holds no such image.

    The stub looks for the image where the MZ header says the stub itself ends, so the offset is the file size
    that the header's page count and final-page byte count declare. The image must be an i386 COFF executable
    with an a.out header, since that header is where the entry point comes from.
    """
    stream.seek(0)
    head = stream.read(6)
    if len(head) < 6 or head[:2] != b"MZ":
        stream.seek(0)
        return None
    bytes_in_last_page, pages_in_file = struct.unpack("<HH", head[2:])
    offset = pages_in_file * 512 - (512 - bytes_in_last_page if bytes_in_last_page else 0)
    if offset <= 0:
        stream.seek(0)
        return None
    stream.seek(offset)
    headers = stream.read(ctypes.sizeof(CoffFileHeader) + ctypes.sizeof(AoutHeader))
    stream.seek(0)
    if len(headers) < ctypes.sizeof(CoffFileHeader) + ctypes.sizeof(AoutHeader):
        return None
    header = CoffFileHeader.from_buffer_copy(headers)
    aout = AoutHeader.from_buffer_copy(headers, ctypes.sizeof(CoffFileHeader))
    if (
        header.Machine != IMAGE_FILE_MACHINE.I386
        or header.SizeOfOptionalHeader != ctypes.sizeof(AoutHeader)
        or aout.magic != _ZMAGIC
    ):
        return None
    return offset


class Go32Section(Section):
    """
    A section of a go32 COFF image, with permissions taken from its STYP flags.
    """

    def __init__(self, name: str, offset: int, vaddr: int, size: int, flags: int):
        super().__init__(name, offset, vaddr, size)
        self.flags = flags
        if self.only_contains_uninitialized_data:
            self.filesize = 0

    @property
    def is_readable(self):
        return True

    @property
    def is_writable(self):
        return not self.flags & STYP.TEXT

    @property
    def is_executable(self):
        return bool(self.flags & STYP.TEXT)

    @property
    def only_contains_uninitialized_data(self):
        return bool(self.flags & STYP.BSS)


class Go32(Backend):
    """
    Loader for DJGPP go32 executables.

    The file is a real-mode MZ stub followed by an i386 COFF executable. The stub gets protected-mode memory from a
    DPMI host, reads the COFF image's text and data sections to their virtual addresses, zero-fills bss and jumps
    to the a.out header's entry point. This backend loads that image and leaves the stub out.
    """

    is_default = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        image = coff_image_offset(self._binary_stream)
        if image is None:
            raise CLEInvalidBinaryError("Not a DJGPP go32 executable: no i386 COFF image follows the MZ stub")
        self._binary_stream.seek(0)
        data = self._binary_stream.read()

        header = CoffFileHeader.from_buffer_copy(data, image)
        aout = AoutHeader.from_buffer_copy(data, image + ctypes.sizeof(CoffFileHeader))

        self.set_arch(archinfo.ArchX86())
        self.os = "dos"
        self.linking = "static"
        self.mapped_base = self.linked_base = 0
        self._entry = aout.entry

        sections = {}
        table = image + ctypes.sizeof(CoffFileHeader) + header.SizeOfOptionalHeader
        for index in range(header.NumberOfSections):
            entry_offset = table + index * ctypes.sizeof(CoffSectionTableEntry)
            if entry_offset + ctypes.sizeof(CoffSectionTableEntry) > len(data):
                raise CLEInvalidBinaryError(f"Truncated go32 COFF section table: section {index} is past the file")
            entry = CoffSectionTableEntry.from_buffer_copy(data, entry_offset)
            flags = STYP(entry.Characteristics & (STYP.TEXT | STYP.DATA | STYP.BSS))
            if not flags:
                # debugging and comment sections, which the stub does not load
                continue

            name = bytes(entry.Name).rstrip(b"\0").decode("ascii", "replace")
            size = entry.SizeOfRawData
            if flags & STYP.BSS:
                offset = 0
                content = bytes(size)
            else:
                offset = image + entry.PointerToRawData
                content = data[offset : offset + size]
                if len(content) != size:
                    raise CLEInvalidBinaryError(f"Truncated go32 COFF section {name}: its contents run past the file")
            if content:
                self.memory.add_backer(entry.VirtualAddress, content)
            section = Go32Section(name, offset, entry.VirtualAddress, size, flags)
            self.sections.append(section)
            self.segments.append(Segment(offset, entry.VirtualAddress, section.filesize, size))
            sections[index + 1] = section

        if header.NumberOfSymbols:
            self._load_symbols(data, image + header.PointerToSymbolTable, header.NumberOfSymbols, sections)

    def _load_symbols(self, data: bytes, table: int, count: int, sections: dict[int, Go32Section]) -> None:
        """
        Add the symbols defined in a loaded section. A COFF executable stores their virtual addresses.
        """
        strings = table + count * ctypes.sizeof(CoffSymbolTableEntry)
        if strings > len(data):
            log.warning("go32 COFF symbol table runs past the end of the file; loading no symbols")
            return

        index = 0
        while index < count:
            entry = CoffSymbolTableEntry.from_buffer_copy(data, table + index * ctypes.sizeof(CoffSymbolTableEntry))
            index += 1 + entry.NumberOfAuxSymbols
            section = sections.get(entry.SectionNumber)
            if section is None or entry.StorageClass not in (
                IMAGE_SYM_CLASS.EXTERNAL,
                IMAGE_SYM_CLASS.STATIC,
                IMAGE_SYM_CLASS.LABEL,
            ):
                continue

            raw_name = bytes(entry.Name)
            if raw_name[:4] == b"\0\0\0\0":
                start = strings + struct.unpack("<I", raw_name[4:])[0]
                end = data.find(b"\0", start)
                raw_name = data[start:end] if end >= 0 else b""
            name = raw_name.rstrip(b"\0").decode("ascii", "replace")
            if entry.StorageClass == IMAGE_SYM_CLASS.STATIC and name == section.name:
                # the section symbol each linked object file contributes
                continue

            # a GNU-built COFF executable usually leaves the type field 0, so the section says what a symbol is
            if entry.StorageClass == IMAGE_SYM_CLASS.LABEL:
                symbol_type = SymbolType.TYPE_OTHER
            elif section.is_executable:
                symbol_type = SymbolType.TYPE_FUNCTION
            else:
                symbol_type = SymbolType.TYPE_OBJECT
            self.symbols.add(Symbol(self, name, entry.Value, 0, symbol_type))

    @classmethod
    def is_compatible(cls, stream):
        return coff_image_offset(stream) is not None


register_backend("go32", Go32)
