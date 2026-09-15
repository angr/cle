from __future__ import annotations

import os
from unittest import TestCase, main

from elftools.dwarf import callframe
from elftools.elf.elffile import ELFFile

import cle
from cle.backends.backend import FunctionHintSource
from cle.backends.elf.eh_frame import parse_fde_ranges

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestEhFrame(TestCase):
    def _reference_fdes(self, path: str) -> list[tuple[int, int]]:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            mask = (1 << elf.elfclass) - 1
            dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False, follow_links=False)
            return [
                (entry.header["initial_location"] & mask, entry.header["address_range"])
                for entry in dwarf.EH_CFI_entries()
                if isinstance(entry, callframe.FDE)
            ]

    def test_fast_walker_matches_pyelftools(self):
        for rel in (
            "x86_64/fauxware",
            "i386/fauxware",
            "ppc64/fauxware",
            "s390x/fauxware",
            "x86_64/tailcall_dispatch_cet",
        ):
            path = os.path.join(TESTS_BASE, rel)
            with open(path, "rb") as f:
                elf = ELFFile(f)
                section = elf.get_section_by_name(".eh_frame")
                assert section is not None
                fast = parse_fde_ranges(section.data(), section["sh_addr"], elf.elfclass // 8, elf.little_endian)
            assert fast, rel
            assert fast == self._reference_fdes(path), rel

    def test_hints_available_without_debug_info(self):
        path = os.path.join(TESTS_BASE, "x86_64", "tailcall_dispatch_cet")
        loader = cle.Loader(path, auto_load_libs=False)
        assert not loader._load_debug_info
        obj = loader.main_object
        hints = [h for h in obj.function_hints if h.source == FunctionHintSource.EH_FRAME]
        expected = self._reference_fdes(path)
        assert len(hints) == len(expected) == 12
        # hints carry the mapped address, references are link-time addresses of a PIE
        assert sorted(h.addr - obj.mapped_base for h in hints) == sorted(a for a, _ in expected)
        assert {h.size for h in hints} == {size for _, size in expected}

    def test_hints_not_duplicated_with_debug_info(self):
        path = os.path.join(TESTS_BASE, "x86_64", "tailcall_dispatch_cet")
        loader = cle.Loader(path, auto_load_libs=False, load_debug_info=True)
        hints = [h for h in loader.main_object.function_hints if h.source == FunctionHintSource.EH_FRAME]
        assert len(hints) == 12


if __name__ == "__main__":
    main()
