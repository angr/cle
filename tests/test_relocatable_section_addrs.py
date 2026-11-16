from __future__ import annotations

import os
import unittest

import cle
from cle.address_translator import AT
from cle.backends.elf.regions import ELFSection

TESTS_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)
BINARY = os.path.join(TESTS_BASE, "x86_64", "switch_default_abort.o")

PINNED_TEXT = 0x10000
PINNED_RODATA = 0x20000


class TestRelocatableSectionAddrs(unittest.TestCase):
    """
    A relocatable object (ET_REL) carries no meaningful section addresses, so cle lays its sections out by
    emulating a linker. The ``section_addrs`` option lets a caller pin sections to specific addresses instead,
    so that cle's layout can match an external tool (e.g. Ghidra).
    """

    @staticmethod
    def _load(**main_opts):
        return cle.Loader(BINARY, auto_load_libs=False, main_opts=main_opts)

    @staticmethod
    def _lva(ld, name):
        # the requested address is a link-time address, so compare in LVA space to be independent of any rebase
        return AT.from_mva(ld.main_object.sections_map[name].vaddr, ld.main_object).to_lva()

    def test_sections_are_pinned_to_requested_addresses(self):
        ld = self._load(section_addrs={".text": PINNED_TEXT, ".rodata": PINNED_RODATA})

        self.assertEqual(self._lva(ld, ".text"), PINNED_TEXT)
        self.assertEqual(self._lva(ld, ".rodata"), PINNED_RODATA)

        # the pinned sections really occupy those addresses
        text = ld.main_object.sections_map[".text"]
        rodata = ld.main_object.sections_map[".rodata"]
        text_containing = ld.main_object.find_section_containing(text.vaddr)
        rodata_containing = ld.main_object.find_section_containing(rodata.vaddr)
        assert text_containing is not None and rodata_containing is not None
        self.assertEqual(text_containing.name, ".text")
        self.assertEqual(rodata_containing.name, ".rodata")

    def test_default_layout_is_unchanged_without_the_option(self):
        ld = self._load()
        # without the option, cle's own layout must not accidentally equal the pinned address
        self.assertNotEqual(self._lva(ld, ".text"), PINNED_TEXT)

    def test_unlisted_sections_do_not_crash_the_load(self):
        ld = self._load(section_addrs={".text": PINNED_TEXT})
        self.assertEqual(self._lva(ld, ".text"), PINNED_TEXT)
        # every other section still has a usable address
        for section in ld.main_object.sections:
            if isinstance(section, ELFSection) and section.occupies_memory:
                self.assertGreaterEqual(section.vaddr, 0)


if __name__ == "__main__":
    unittest.main()
