# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from pathlib import PurePosixPath
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestDwarf(TestCase):
    def test_line_program_file_indices(self):
        load_options = (
            (0x400000, {}),
            (0x700000, {"base_addr": 0x700000, "force_rebase": True}),
        )
        for variant in ("v4", "v5_relative", "v5_absolute"):
            binary_path = os.path.join(TESTS_BASE, "x86_64", f"dwarf_line_filenames_{variant}")
            for base_addr, main_opts in load_options:
                with self.subTest(variant=variant, base_addr=base_addr):
                    ld = cle.Loader(
                        binary_path,
                        auto_load_libs=False,
                        load_debug_info=True,
                        main_opts=main_opts,
                    )
                    elf = ld.main_object
                    assert isinstance(elf, cle.backends.ELF)
                    assert elf.mapped_base == base_addr
                    assert elf.compilation_units is not None and len(elf.compilation_units) == 1
                    comp_dir = PurePosixPath(elf.compilation_units[0].comp_dir)
                    assert comp_dir.is_absolute()

                    main_symbol = elf.get_symbol("main")
                    increment_symbol = elf.get_symbol("increment")
                    assert main_symbol is not None
                    assert increment_symbol is not None
                    main_path = comp_dir / "main.c"
                    header_path = comp_dir / "include" / "header.h"
                    assert elf.addr_to_line[main_symbol.rebased_addr] == {(str(main_path), 4)}
                    assert elf.addr_to_line[increment_symbol.rebased_addr] == {(str(header_path), 2)}

    def test_rust_binary(self):
        binary_path = os.path.join(
            TESTS_BASE, "x86_64", "1cbbf108f44c8f4babde546d26425ca5340dccf878d306b90eb0fbec2f83ab51"
        )
        ld = cle.Loader(binary_path, auto_load_libs=False, load_debug_info=True, main_opts={"base_addr": 0x400000})
        elf = ld.main_object
        assert isinstance(elf, cle.backends.ELF)
        # item with abstract origin
        subroutine = elf.functions_debug_info[0x0043FC10]
        assert subroutine.name == "panic_unwind::real_imp::find_eh_action::{closure#0}"
        # item with tracked namespace
        subroutine = elf.functions_debug_info[0x0043FBF0]
        assert subroutine.name == "panic_unwind::real_imp::panic::exception_cleanup"

        # item with inlined functions
        subroutine = elf.functions_debug_info[0x0043FC30]
        assert len(subroutine.inlined_functions) >= 1
        inlined = [
            i for i in subroutine.inlined_functions if i.name == "panic_unwind::real_imp::rust_eh_personality_impl"
        ]
        assert len(inlined) == 1
        assert inlined[0].ranges == [(0x43FC49, 0x43FEA6), (0x43FEC4, 0x43FEE8)]
        assert inlined[0].low_pc == 0x43FC49
        assert inlined[0].high_pc == 0x43FEE8


if __name__ == "__main__":
    main()
