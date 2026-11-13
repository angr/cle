"""Tests for the function hints cle derives from .eh_frame."""

from __future__ import annotations

import os
from unittest import TestCase, main

import cle
from cle.backends import FunctionHintSource

HERE = os.path.dirname(os.path.realpath(__file__))
TESTS_BASE = os.path.join(HERE, "..", "..", "binaries", "tests")


class TestEhFrameHints(TestCase):
    """The hints must be available without asking the loader for debug information."""

    @staticmethod
    def _hints(*path, **kwargs):
        loader = cle.Loader(os.path.join(TESTS_BASE, *path), auto_load_libs=False, **kwargs)
        return loader, loader.main_object.function_hints

    def test_hints_are_loaded_without_debug_info(self):
        """CFGFast enables eh_frame by default, so hints must exist without load_debug_info."""
        loader, hints = self._hints("x86_64", "fauxware")
        assert len(hints) == 7
        assert all(hint.source == FunctionHintSource.EH_FRAME for hint in hints)
        assert all(loader.main_object.contains_addr(hint.addr) for hint in hints)

    def test_hints_are_loaded_for_a_stripped_binary(self):
        """A stripped binary is the case that needs this most: .eh_frame outlives .symtab."""
        loader, hints = self._hints("x86_64", "true")
        assert loader.main_object.get_symbol("main") is None
        assert len(hints) == 70

    def test_debug_info_does_not_load_the_hints_twice(self):
        """Asking for debug info must not add a second copy of every hint."""
        _, without = self._hints("x86_64", "fauxware")
        _, with_debug = self._hints("x86_64", "fauxware", load_debug_info=True)
        assert len(with_debug) == len(without)

    def test_hints_survive_debug_sections_that_do_not_parse(self):
        """.eh_frame needs no DWARF relocation, so relocating .debug_* must not gate it."""
        _, hints = self._hints("x86_64", "dir_gcc_-O0")
        assert len(hints) == 395

    def test_relocatable_objects_get_no_hints(self):
        """An FDE address in ET_REL is section-relative, so a hint from it points nowhere."""
        for load_debug_info in (False, True):
            _, hints = self._hints("x86_64", "copy.o", load_debug_info=load_debug_info)
            assert hints == []

    def test_a_cie_without_an_fde_encoding_does_not_fail_the_load(self):
        """The "R" augmentation is optional; reading .eh_frame must not cost a load."""
        _, hints = self._hints("mips", "busybox")
        assert hints == []


if __name__ == "__main__":
    main()
