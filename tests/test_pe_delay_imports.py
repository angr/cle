# pylint: disable=missing-class-docstring,no-self-use
"""Tests for delay-load import binding in the PE backend.

The fixture ``delay_import.exe`` (built from ``binaries/tests_src/delay_import.c`` via
``delay_import.build.sh``) delay-loads ``user32.dll!MessageBoxA``: its descriptor lives in the delay-import data
directory rather than the normal import directory, and its IAT slot points at a ``__delayLoadHelper2`` binding thunk.
The loader should bind it just like a regular import -- creating an import symbol and relocating the delay IAT slot to
the resolved (here: extern stub) address.
"""

from __future__ import annotations

import os
import unittest

import pefile

import cle

TEST_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests", "x86_64", "windows"
)
FIXTURE = os.path.join(TEST_BASE, "delay_import.exe")


class TestPeDelayImports(unittest.TestCase):
    def test_fixture_actually_delay_imports(self):
        # guard: the fixture must import MessageBoxA via the delay-import directory, not the normal one
        pe = pefile.PE(FIXTURE)
        pe.parse_data_directories()
        delay = {
            imp.name.decode()
            for entry in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])
            for imp in entry.imports
            if imp.name is not None
        }
        regular = {
            imp.name.decode()
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
            for imp in entry.imports
            if imp.name is not None
        }
        self.assertIn("MessageBoxA", delay)
        self.assertNotIn("MessageBoxA", regular)

    def test_delay_import_is_bound(self):
        ld = cle.Loader(FIXTURE, auto_load_libs=False)
        obj = ld.main_object

        # the delay import shows up as a normal import with a DLL-import relocation
        self.assertIn("MessageBoxA", obj.imports)
        reloc = obj.imports["MessageBoxA"]

        sym = ld.find_symbol("MessageBoxA")
        self.assertIsNotNone(sym)
        self.assertTrue(sym.is_import or sym.is_extern)

        # the delay IAT slot has been relocated to the resolved address instead of the in-image binding thunk
        slot_addr = reloc.rebased_addr
        self.assertEqual(ld.memory.unpack_word(slot_addr, size=8), sym.rebased_addr)


if __name__ == "__main__":
    unittest.main()
