from __future__ import annotations

import struct
from collections import namedtuple
from typing import cast

import archinfo

from . import Backend, Section, register_backend
from .coff import IMAGE_SCN
from .region import Segment
from .regions import Regions

HEADER = struct.Struct("<HHBBHIIQIIII")
SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")
HeaderType = namedtuple(
    "HeaderType",
    (
        "signature",
        "machine",
        "number_of_sections",
        "subsystem",
        "stripped_size",
        "address_of_entry_point",
        "base_of_code",
        "image_base",
        "data_directory_0_virtual_address",
        "data_directory_0_size",
        "data_directory_1_virtual_address",
        "data_directory_1_size",
    ),
)
SectionHeaderType = namedtuple(
    "SectionHeaderType",
    (
        "section_name",
        "physical_address_virtual_size",
        "virtual_address",
        "size_of_raw_data",
        "pointer_to_raw_data",
        "pointer_to_relocations",
        "pointer_to_line_numbers",
        "number_of_relocations",
        "number_of_line_numbers",
        "characteristics",
    ),
)

ARCH_MAPPING = {
    0x014C: "i386",
    0x0200: "IPF",
    0x0EBC: "EBC",
    0x8664: "X64",
    0x01C0: "ARM Cortex-M",
    0x01C2: "ARM",
    0xAA64: "AARCH64",
}


class TESection(Section):
    """
    A section of a Terse Executable image.
    """

    def __init__(self, section_header: SectionHeaderType, linked_base: int, stripped_offset: int):
        super().__init__(
            section_header.section_name.rstrip(b"\0").decode(),
            # pointer_to_raw_data indexes the pre-strip PE file, not the TE file
            section_header.pointer_to_raw_data - stripped_offset,
            section_header.virtual_address + linked_base,
            section_header.physical_address_virtual_size,
        )
        # the base class assumes filesize == memsize; only size_of_raw_data bytes are backed
        self.filesize = section_header.size_of_raw_data
        self.characteristics = section_header.characteristics

    @property
    def is_readable(self):
        return self.characteristics & IMAGE_SCN.MEM_READ != 0

    @property
    def is_writable(self):
        return self.characteristics & IMAGE_SCN.MEM_WRITE != 0

    @property
    def is_executable(self):
        return self.characteristics & IMAGE_SCN.MEM_EXECUTE != 0

    @property
    def only_contains_uninitialized_data(self):
        # zero-filled whether or not the linker sets IMAGE_SCN.CNT_UNINITIALIZED_DATA
        return self.filesize == 0


class TE(Backend):
    """
    A "Terse Executable" format image, commonly used as part of UEFI firmware drivers.
    """

    is_default = True

    @classmethod
    def is_compatible(cls, stream):
        stream.seek(0)
        return stream.read(2) == b"VZ"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._binary_stream.seek(0)
        self.header = HeaderType(*HEADER.unpack(self._binary_stream.read(HEADER.size)))
        self.section_headers = [
            SectionHeaderType(*SECTION_HEADER.unpack(self._binary_stream.read(SECTION_HEADER.size)))
            for _ in range(self.header.number_of_sections)
        ]

        self.set_arch(archinfo.arch_from_id(ARCH_MAPPING[self.header.machine]))

        stripped_offset = self.header.stripped_size - HEADER.size
        self.linked_base = self.mapped_base = self.header.image_base + stripped_offset
        # an RVA, in the same space as the section virtual addresses below
        self._entry = self.linked_base + self.header.address_of_entry_point

        for section_header in self.section_headers:
            section = TESection(section_header, self.linked_base, stripped_offset)
            self._sections.append(section)

            if (
                section_header.characteristics & IMAGE_SCN.MEM_DISCARDABLE != 0
                or section_header.physical_address_virtual_size == 0
            ):
                # discard or no data
                continue
            self._binary_stream.seek(section.offset)
            data = self._binary_stream.read(section.filesize)
            assert len(data) == section.filesize
            # zero-fill up to the virtual size; ljust takes the total width, not the shortfall
            data = data.ljust(section.memsize, b"\0")
            self.memory.add_backer(section_header.virtual_address, data)

        # in a TE image, as in the PE image it was stripped from, sections and segments have the same meaning
        self._segments = cast(Regions[Segment], self._sections)

        # the TE header's first data directory is the base relocation table, so an image with relocation entries
        # can be rebased
        self.pic = self.header.data_directory_0_size != 0


register_backend("te", TE)
