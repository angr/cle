# pylint: disable=missing-class-docstring,no-self-use
"""Base relocations of a PE loaded at its preferred base must leave memory untouched."""

from __future__ import annotations

import io
import os
import struct
import unittest

import pefile

import cle

BINARY = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests", "x86_64", "windows", "fauxware.exe"
)


class TestPePreferredBase(unittest.TestCase):
    def setUp(self):
        with open(BINARY, "rb") as fp:
            data = bytearray(fp.read())
        pe = pefile.PE(data=bytes(data), fast_load=True)
        reloc_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
        block = pe.get_offset_from_rva(reloc_dd.VirtualAddress)
        block_va = struct.unpack_from("<I", data, block)[0]
        offset = struct.unpack_from("<H", data, block + 8)[0] & 0xFFF
        # turn the first entry into IMAGE_REL_BASED_HIGH, whose fixup is not the identity at the preferred base
        struct.pack_into("<H", data, block + 8, (1 << 12) | offset)
        self.data = bytes(data)
        self.image_base = pe.OPTIONAL_HEADER.ImageBase
        self.rva = block_va + offset
        self.original = data[pe.get_offset_from_rva(self.rva) :][:8]

    def test_preferred_base_keeps_bytes(self):
        ld = cle.Loader(io.BytesIO(self.data), auto_load_libs=False)
        assert ld.main_object.mapped_base == self.image_base
        assert ld.memory.load(self.image_base + self.rva, 8) == self.original

    def test_rebased_image_is_relocated(self):
        base = self.image_base + 0x20000
        ld = cle.Loader(io.BytesIO(self.data), auto_load_libs=False, main_opts={"base_addr": base})
        assert ld.memory.load(base + self.rva, 8) != self.original


if __name__ == "__main__":
    unittest.main()
