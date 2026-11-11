# pylint: disable=missing-class-docstring,no-self-use
"""The PE backend reads the x64 RUNTIME_FUNCTION table itself; its function hints must match pefile's parse."""

from __future__ import annotations

import io
import os
import struct
import unittest

import pefile

import cle
from cle.backends.backend import FunctionHintSource
from cle.structs import MemRegionSort

BINARY = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests", "x86_64", "windows", "fauxware.exe"
)


def _pefile_hints(data: bytes) -> list[tuple[int, int]]:
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
    base = pe.OPTIONAL_HEADER.ImageBase
    return [
        (base + e.struct.BeginAddress, e.struct.EndAddress - e.struct.BeginAddress)
        for e in getattr(pe, "DIRECTORY_ENTRY_EXCEPTION", [])
    ]


def _cle_hints(data: bytes) -> tuple[list[tuple[int, int]], bool]:
    obj = cle.Loader(io.BytesIO(data), auto_load_libs=False).main_object
    hints = [(h.addr, h.size) for h in obj.function_hints if h.source == FunctionHintSource.EH_FRAME]
    has_region = any(r.sort == MemRegionSort.EXCEPTION_DIRECTORY for r in obj.meta_regions)
    return hints, has_region


def _runtime_function_offsets(data: bytes) -> tuple[pefile.PE, list[int]]:
    """File offsets of the RUNTIME_FUNCTION entries."""
    pe = pefile.PE(data=data, fast_load=True)
    exc_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    start = pe.get_offset_from_rva(exc_dd.VirtualAddress)
    return pe, [start + i * 12 for i in range(exc_dd.Size // 12)]


class TestPeExceptionDirectory(unittest.TestCase):
    def test_amd64(self):
        with open(BINARY, "rb") as fp:
            data = fp.read()
        pe, offsets = _runtime_function_offsets(data)

        # matches pefile
        want = _pefile_hints(data)
        assert len(want) == 117
        assert _cle_hints(data) == (want, True)

        # unsupported unwind version ends the table
        patched = bytearray(data)
        (unwind_rva,) = struct.unpack_from("<I", patched, offsets[50] + 8)
        unwind_off = pe.get_offset_from_rva(unwind_rva)
        patched[unwind_off] = (patched[unwind_off] & ~7) | 3
        want = _pefile_hints(bytes(patched))
        assert 0 < len(want) <= 50
        assert _cle_hints(bytes(patched)) == (want, True)

        # unreadable unwind info drops the table
        patched = bytearray(data)
        struct.pack_into("<I", patched, offsets[10] + 8, 0x7FFFFFF0)
        assert not _pefile_hints(bytes(patched))
        assert _cle_hints(bytes(patched)) == ([], False)


if __name__ == "__main__":
    unittest.main()
