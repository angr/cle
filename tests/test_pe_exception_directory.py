# pylint: disable=missing-class-docstring,no-self-use
"""
The PE backend reads exception directories itself. AMD64 hints must match pefile's parse; ARM64 and ARMNT hints (which
pefile does not parse) were checked entry by entry against ``llvm-readobj --unwind``.
"""

from __future__ import annotations

import io
import os
import struct
import unittest

import pefile

import cle
from cle.backends.backend import FunctionHintSource
from cle.structs import MemRegionSort

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
BINARY = os.path.join(TEST_BASE, "x86_64", "windows", "fauxware.exe")
ARM64_BINARY = os.path.join(TEST_BASE, "aarch64", "windows", "pdata_arm64.exe")
ARMNT_BINARY = os.path.join(TEST_BASE, "armel", "windows", "pdata_armnt.exe")


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


def _runtime_function_offsets(data: bytes, entry_size: int = 12) -> tuple[pefile.PE, list[int]]:
    """File offsets of the exception directory entries."""
    pe = pefile.PE(data=data, fast_load=True)
    exc_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    start = pe.get_offset_from_rva(exc_dd.VirtualAddress)
    return pe, [start + i * entry_size for i in range(exc_dd.Size // entry_size)]


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

    def test_arm(self):
        # ARMNT
        obj = cle.Loader(ARMNT_BINARY, auto_load_libs=False).main_object
        hints = [(h.addr, h.size) for h in obj.function_hints if h.source == FunctionHintSource.EH_FRAME]
        assert len(hints) == 34
        assert all(addr & 1 for addr, _ in hints)  # Thumb code: the start addresses keep the low bit
        assert hints[0] == (0x401001, 28)  # .xdata
        assert hints[11] == (0x4014C1, 104)  # packed

        # ARM64
        obj = cle.Loader(ARM64_BINARY, auto_load_libs=False).main_object
        hints = [(h.addr, h.size) for h in obj.function_hints if h.source == FunctionHintSource.EH_FRAME]
        assert obj.arch.name == "AARCH64"
        assert len(hints) == 21
        assert hints[2] == (0x1400014D4, 36)  # small_frame, packed
        assert hints[3] == (0x1400014F8, 76)  # large_frame, .xdata
        assert hints[9] == (0x140001918, 200)  # main, .xdata
        (region,) = (r for r in obj.meta_regions if r.sort == MemRegionSort.EXCEPTION_DIRECTORY)
        assert (region.sub_regions[0].entry_size, region.sub_regions[0].count) == (8, 21)

        with open(ARM64_BINARY, "rb") as fp:
            data = fp.read()
        pe, offsets = _runtime_function_offsets(data, 8)

        # fragments are kept
        patched = bytearray(data)
        (unwind,) = struct.unpack_from("<I", patched, offsets[2] + 4)
        assert unwind & 3 == 1
        struct.pack_into("<I", patched, offsets[2] + 4, unwind ^ 3)  # packed -> packed fragment
        assert _cle_hints(bytes(patched)) == (hints, True)

        # reserved flag ends the table
        patched = bytearray(data)
        struct.pack_into("<I", patched, offsets[5] + 4, 3)
        assert _cle_hints(bytes(patched)) == (hints[:5], True)

        # unsupported .xdata version ends the table
        patched = bytearray(data)
        (xdata,) = struct.unpack_from("<I", patched, offsets[3] + 4)
        assert xdata & 3 == 0
        patched[pe.get_offset_from_rva(xdata) + 2] |= 1 << 2  # Vers = 1
        assert _cle_hints(bytes(patched)) == (hints[:3], True)

        # unreadable .xdata drops the table
        patched = bytearray(data)
        struct.pack_into("<I", patched, offsets[10] + 4, 0x7FFFFFF0)
        assert _cle_hints(bytes(patched)) == ([], False)


if __name__ == "__main__":
    unittest.main()
