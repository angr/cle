from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

import archinfo

from cle.errors import CLEInvalidBinaryError, CLEOperationError
from cle.utils import stream_or_path

from .backend import Backend, register_backend
from .region import Segment
from .relocation import Relocation

__all__ = ("MZ", "MZHeader", "MZRelocation")


_FIXED_HEADER_SIZE = 0x1C
_EXTENDED_HEADER_POINTER_OFFSET = 0x3C
_EXTENDED_HEADER_POINTER_END = 0x40
_PAGE_SIZE = 512
_PARAGRAPH_SIZE = 16
_REAL_MODE_ADDRESS_SPACE = 1 << 20
_EXTENDED_SIGNATURES = frozenset({b"NE", b"LE", b"LX", b"W3", b"W4"})


class _Reader:
    """Bounded random-access reads from an MZ input stream."""

    def __init__(self, stream: BinaryIO):
        self._stream = stream
        try:
            original = stream.tell()
            stream.seek(0, os.SEEK_END)
            self.size = stream.tell()
            stream.seek(original)
        except (OSError, OverflowError, ValueError) as exc:
            raise CLEInvalidBinaryError("MZ input is not a seekable binary stream") from exc

    def read(self, offset: int, size: int, description: str) -> bytes:
        if offset < 0 or size < 0 or offset > self.size or size > self.size - offset:
            raise CLEInvalidBinaryError(
                f"Truncated MZ {description}: range {offset:#x}..{offset + size:#x} exceeds file size {self.size:#x}"
            )
        try:
            self._stream.seek(offset)
            data = self._stream.read(size)
        except (OSError, OverflowError, ValueError) as exc:
            raise CLEInvalidBinaryError(f"Cannot read MZ {description} at {offset:#x}") from exc
        if len(data) != size:
            raise CLEInvalidBinaryError(f"Truncated MZ {description} at {offset:#x}")
        return data


@dataclass(frozen=True, slots=True)
class MZHeader:
    """The fixed DOS MZ executable header."""

    bytes_in_last_page: int
    pages_in_file: int
    relocation_count: int
    header_paragraphs: int
    minimum_extra_paragraphs: int
    maximum_extra_paragraphs: int
    initial_ss: int
    initial_sp: int
    checksum: int
    initial_ip: int
    initial_cs: int
    relocation_table_offset: int
    overlay_number: int

    @property
    def header_size(self) -> int:
        return self.header_paragraphs * _PARAGRAPH_SIZE

    @property
    def declared_file_size(self) -> int:
        final_page_size = self.bytes_in_last_page or _PAGE_SIZE
        return (self.pages_in_file - 1) * _PAGE_SIZE + final_page_size

    @property
    def image_size(self) -> int:
        return self.declared_file_size - self.header_size

    @property
    def entry_rva(self) -> int:
        return self.initial_cs * _PARAGRAPH_SIZE + self.initial_ip

    @property
    def stack_rva(self) -> int:
        return self.initial_ss * _PARAGRAPH_SIZE + self.initial_sp

    @property
    def minimum_allocation_size(self) -> int:
        image_paragraphs = (self.image_size + _PARAGRAPH_SIZE - 1) // _PARAGRAPH_SIZE
        return (image_paragraphs + self.minimum_extra_paragraphs) * _PARAGRAPH_SIZE


class MZRelocation(Relocation):
    """A DOS load-segment relocation applied to a word in the load module."""

    __slots__ = ("offset", "segment")

    def __init__(self, owner: MZ, offset: int, segment: int):
        self.offset = offset
        self.segment = segment
        super().__init__(owner, None, segment * _PARAGRAPH_SIZE + offset)
        self.resolved = True

    @property
    def value(self) -> int:
        return self.owner.load_segment

    def relocate(self):
        current = self.owner.memory.unpack_word(self.dest_addr, size=2)
        self.owner.memory.pack_word(self.dest_addr, (current + self.value) & 0xFFFF, size=2)
        return True


class MZ(Backend):
    """Loader for ordinary 8086 DOS MZ executables.

    The load module is represented in a canonical 20-bit linear address space:
    ``segment * 16 + offset``. The Program Segment Prefix and runtime-selected
    extra allocation beyond the header's required minimum are not materialized.
    """

    is_default = True
    ADDRESS_MODEL = "dos-mz-linear20-v1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        reader = _Reader(self._binary_stream)
        self.mz_header = self._parse_header(reader)
        extension = self._recognized_extension(reader, self.mz_header)
        if extension is not None:
            raise CLEInvalidBinaryError(f"MZ container has an extended {extension.decode('ascii')} executable header")
        relocation_records = self._parse_relocations(reader, self.mz_header)

        try:
            self.set_arch(archinfo.ArchPcode("x86:LE:16:Real Mode"))
        except archinfo.ArchError as exc:
            raise CLEInvalidBinaryError("Cannot construct the required DOS MZ p-code architecture") from exc

        self.os = "dos"
        self.mapped_base = self.linked_base = 0
        self.address_model = self.ADDRESS_MODEL
        self.execution_mode = "real"
        self.linking = "static"
        self.execstack = True

        header = self.mz_header
        self.initial_cs = header.initial_cs
        self.initial_ip = header.initial_ip
        self.initial_ss = header.initial_ss
        self.initial_sp = header.initial_sp
        self.minimum_extra_paragraphs = header.minimum_extra_paragraphs
        self.maximum_extra_paragraphs = header.maximum_extra_paragraphs
        self.overlay_number = header.overlay_number
        self.declared_file_size = header.declared_file_size
        self.trailing_size = reader.size - header.declared_file_size
        self._entry = header.entry_rva

        image = reader.read(header.header_size, header.image_size, "load module")
        self.memory.add_backer(0, image)
        self.segments = [
            Segment(
                header.header_size,
                0,
                header.image_size,
                header.minimum_allocation_size,
            )
        ]

        for offset, segment in relocation_records:
            self.relocs.append(MZRelocation(self, offset, segment))

    @property
    def mapped_address_bits(self) -> int:
        return 20

    @property
    def load_segment(self) -> int:
        return self.mapped_base // _PARAGRAPH_SIZE

    @property
    def initial_stack(self) -> int:
        """The canonical linear address corresponding to the initial SS:SP."""
        return self.mapped_base + self.mz_header.stack_rva

    @property
    def initial_cs_value(self) -> int:
        """The CS register value after DOS adds the runtime load segment."""
        return (self.load_segment + self.initial_cs) & 0xFFFF

    @property
    def initial_ss_value(self) -> int:
        """The SS register value after DOS adds the runtime load segment."""
        return (self.load_segment + self.initial_ss) & 0xFFFF

    def rebase(self, new_base):
        if new_base < 0:
            raise CLEOperationError(f"DOS MZ load base {new_base:#x} lies outside the 20-bit real-mode address space")
        if new_base % _PARAGRAPH_SIZE:
            raise CLEOperationError(f"DOS MZ load base {new_base:#x} is not paragraph-aligned")
        if new_base + self.mz_header.minimum_allocation_size > _REAL_MODE_ADDRESS_SPACE:
            raise CLEOperationError(f"DOS MZ allocation at {new_base:#x} exceeds the 20-bit real-mode address space")
        super().rebase(new_base)

    @classmethod
    def is_compatible(cls, stream):
        try:
            original = stream.tell()
        except (OSError, ValueError):
            original = 0
        try:
            reader = _Reader(stream)
            header = cls._parse_header(reader)
            if cls._recognized_extension(reader, header) is not None:
                return False
            cls._parse_relocations(reader, header)
            return True
        except (CLEInvalidBinaryError, OSError, OverflowError, ValueError):
            return False
        finally:
            try:
                stream.seek(original)
            except (OSError, OverflowError, ValueError):
                pass

    @classmethod
    def check_magic_compatibility(cls, stream):
        return cls.is_compatible(stream)

    @classmethod
    def check_compatibility(cls, spec, obj):
        if not isinstance(obj, MZ):
            return False
        try:
            with stream_or_path(spec) as stream:
                return cls.is_compatible(stream)
        except (OSError, ValueError):
            return False

    def _cache_content(self):
        # The parser performs bounded reads and deliberately ignores bytes after the declared MZ image.
        return

    @staticmethod
    def _parse_header(reader: _Reader) -> MZHeader:
        data = reader.read(0, _FIXED_HEADER_SIZE, "fixed header")
        fields = struct.unpack("<14H", data)
        if fields[0] != 0x5A4D:
            raise CLEInvalidBinaryError("MZ file does not start with the MZ signature")

        header = MZHeader(*fields[1:])
        if header.pages_in_file == 0:
            raise CLEInvalidBinaryError("MZ header declares zero file pages")
        if header.bytes_in_last_page >= _PAGE_SIZE:
            raise CLEInvalidBinaryError(
                f"MZ final-page byte count {header.bytes_in_last_page:#x} is not smaller than one page"
            )
        if header.declared_file_size > reader.size:
            raise CLEInvalidBinaryError(
                f"Truncated MZ image: header declares {header.declared_file_size:#x} bytes, "
                f"file has {reader.size:#x}"
            )
        if not _FIXED_HEADER_SIZE <= header.header_size <= header.declared_file_size:
            raise CLEInvalidBinaryError(
                f"MZ header size {header.header_size:#x} is invalid for "
                f"the {header.declared_file_size:#x}-byte declared file"
            )
        if header.relocation_count:
            if header.relocation_table_offset < _FIXED_HEADER_SIZE:
                raise CLEInvalidBinaryError("MZ relocation table overlaps the fixed header")
            relocation_end = header.relocation_table_offset + header.relocation_count * 4
            if relocation_end > header.header_size:
                raise CLEInvalidBinaryError("MZ relocation table extends past the executable header")
        if header.overlay_number != 0:
            raise CLEInvalidBinaryError(f"MZ overlay {header.overlay_number} is not an ordinary primary executable")
        if header.entry_rva >= header.image_size:
            raise CLEInvalidBinaryError(
                f"MZ entry point {header.initial_cs:04x}:{header.initial_ip:04x} lies outside the load module"
            )
        if header.minimum_allocation_size > _REAL_MODE_ADDRESS_SPACE:
            raise CLEInvalidBinaryError("MZ minimum allocation exceeds the 20-bit real-mode address space")
        if header.stack_rva > header.minimum_allocation_size:
            raise CLEInvalidBinaryError(
                f"MZ initial stack {header.initial_ss:04x}:{header.initial_sp:04x} "
                "lies beyond the minimum allocation"
            )

        return header

    @staticmethod
    def _parse_relocations(reader: _Reader, header: MZHeader) -> tuple[tuple[int, int], ...]:
        if header.relocation_count == 0:
            return ()
        table = reader.read(
            header.relocation_table_offset,
            header.relocation_count * 4,
            "relocation table",
        )
        records = []
        for index in range(header.relocation_count):
            offset, segment = struct.unpack_from("<HH", table, index * 4)
            target = segment * _PARAGRAPH_SIZE + offset
            if target + 2 > header.image_size:
                raise CLEInvalidBinaryError(
                    f"MZ relocation {index} target {segment:04x}:{offset:04x} extends past the load module"
                )
            records.append((offset, segment))
        return tuple(records)

    @staticmethod
    def _recognized_extension(reader: _Reader, header: MZHeader) -> bytes | None:
        if header.header_size < _EXTENDED_HEADER_POINTER_END or reader.size < _EXTENDED_HEADER_POINTER_END:
            return None
        pointer = struct.unpack(
            "<I",
            reader.read(
                _EXTENDED_HEADER_POINTER_OFFSET,
                4,
                "extended-header pointer",
            ),
        )[0]
        if pointer < header.header_size or pointer > reader.size - 2:
            return None
        signature = reader.read(pointer, min(4, reader.size - pointer), "extended-header signature")
        if signature == b"PE\0\0":
            return b"PE"
        if signature[:2] in _EXTENDED_SIGNATURES:
            return signature[:2]
        return None


register_backend("mz", MZ)
