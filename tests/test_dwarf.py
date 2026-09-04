# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestDwarf(TestCase):
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

    def test_dwarf64_line_program(self):
        # The .debug_line units of this binary use the 64-bit DWARF format while the compilation
        # units that reference them use the 32-bit one.
        binary_path = os.path.join(TESTS_BASE, "mips64", "true")
        ld = cle.Loader(binary_path, auto_load_libs=False, load_debug_info=True)
        elf = ld.main_object
        assert isinstance(elf, cle.backends.ELF)
        subroutine = elf.functions_debug_info[0x12000206C]
        assert subroutine.name == "main"
        assert subroutine.source_file == "src/true.c"
        assert ("/home/qinfan/coreutils/coreutils-8.32/src/true.c", 56) in elf.addr_to_line[0x12000206C]


if __name__ == "__main__":
    main()
