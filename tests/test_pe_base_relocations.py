# pylint: disable=missing-class-docstring,no-self-use
"""The PE backend reads the base relocation directory itself; its relocations must match pefile's parse."""

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


def _pefile_relocs(data: bytes) -> list[tuple[int, int]]:
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
    return [(e.rva, e.type) for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []) for e in block.entries]


def _cle_relocs(data: bytes) -> list[tuple[int, int]]:
    obj = cle.Loader(io.BytesIO(data), auto_load_libs=False).main_object
    types = {name: value for value, name in pefile.RELOCATION_TYPE.items() if isinstance(name, str)}
    return [(r.relative_addr, types[type(r).__name__]) for r in obj.relocs if r.symbol is None]


def _block_offsets(data: bytes) -> tuple[pefile.PE, list[int]]:
    """File offsets of the IMAGE_BASE_RELOCATION block headers."""
    pe = pefile.PE(data=data, fast_load=True)
    reloc_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
    offsets = []
    off = pe.get_offset_from_rva(reloc_dd.VirtualAddress)
    end = off + reloc_dd.Size
    while off < end:
        offsets.append(off)
        off += struct.unpack_from("<I", data, off + 4)[0]
    return pe, offsets


class TestPeBaseRelocations(unittest.TestCase):
    def setUp(self):
        with open(BINARY, "rb") as fp:
            self.data = fp.read()

    def test_matches_pefile(self):
        want = _pefile_relocs(self.data)
        assert len(want) == 44
        assert _cle_relocs(self.data) == want

    def test_repeated_entry_ends_the_block(self):
        data = bytearray(self.data)
        _pe, offsets = _block_offsets(self.data)
        # repeat the first entry of the first block as its fourth
        data[offsets[0] + 14 : offsets[0] + 16] = data[offsets[0] + 8 : offsets[0] + 10]
        want = _pefile_relocs(bytes(data))
        assert len(want) < len(_pefile_relocs(self.data))
        assert _cle_relocs(bytes(data)) == want

    def test_block_outside_the_image_ends_the_table(self):
        data = bytearray(self.data)
        pe, offsets = _block_offsets(self.data)
        assert len(offsets) > 2
        struct.pack_into("<I", data, offsets[2], pe.OPTIONAL_HEADER.SizeOfImage + 0x1000)
        want = _pefile_relocs(bytes(data))
        assert 0 < len(want) < len(_pefile_relocs(self.data))
        assert _cle_relocs(bytes(data)) == want


if __name__ == "__main__":
    unittest.main()
