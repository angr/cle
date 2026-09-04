#!/usr/bin/env python
from __future__ import annotations

import os
import unittest

import pefile

import cle
from cle.backends.backend import FunctionHintSource

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

ARM64_PE = os.path.join(TEST_BASE, "tests", "aarch64", "windows", "pe_reloc_arm64.exe")
ARMNT_PE = os.path.join(TEST_BASE, "tests", "armel", "windows", "pe_reloc_armnt.exe")
AMD64_PE = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "sioctl.sys")


def load(path):
    return cle.Loader(path, auto_load_libs=False, main_opts={"backend": "pe"}).main_object


def exception_directory_hints(obj):
    return sorted((h.addr, h.size) for h in obj.function_hints if h.source == FunctionHintSource.EH_FRAME)


# pylint: disable=no-self-use
class TestPEFunctionHints(unittest.TestCase):
    """
    Function hints taken from the exception directory, whose entries have a different shape on
    each architecture.
    """

    def test_aarch64(self):
        obj = load(ARM64_PE)
        base = obj.linked_base
        # the last entry uses the packed form, the first two point at an .xdata record
        assert exception_directory_hints(obj) == [
            (base + 0x1000, 0x138),
            (base + 0x1138, 0x64),
            (base + 0x119C, 0x1C),
        ]

    def test_armnt(self):
        obj = load(ARMNT_PE)
        base = obj.linked_base
        # every function in the image is Thumb, so every start address carries the Thumb bit
        assert exception_directory_hints(obj) == [
            (base + 0x1001, 0xE8),
            (base + 0x10E9, 0x3C),
            (base + 0x1125, 0x1A),
            (base + 0x113F, 0xC),
            (base + 0x114B, 0x10),
            (base + 0x115B, 0xC),
        ]

    def test_armnt_matches_the_function_pointer_table(self):
        obj = load(ARMNT_PE)
        base = obj.linked_base
        # the three entries of the function pointer table name three of the same functions the
        # exception directory does, Thumb bit and all
        table = [obj.memory.unpack_word(0x2000 + i * 4, size=4) for i in range(3)]
        assert sorted(table) == [base + 0x113F, base + 0x114B, base + 0x115B]
        hint_addrs = {addr for addr, _ in exception_directory_hints(obj)}
        assert hint_addrs.issuperset(table)

    def test_x86_64_matches_pefile(self):
        obj = load(AMD64_PE)
        pe = pefile.PE(AMD64_PE, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]])
        entries = getattr(pe, "DIRECTORY_ENTRY_EXCEPTION")  # pefile only sets this for x86-64 and Itanium
        expected = sorted(
            (obj.linked_base + e.struct.BeginAddress, e.struct.EndAddress - e.struct.BeginAddress) for e in entries
        )
        assert exception_directory_hints(obj) == expected


if __name__ == "__main__":
    unittest.main()
