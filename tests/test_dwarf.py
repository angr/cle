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
        ld = cle.Loader(binary_path, auto_load_libs=False, load_debug_info=True)
        elf = ld.main_object
        assert isinstance(elf, cle.backends.ELF)
        # item with abstract origin
        subroutine = elf.functions_debug_info[0x0003FC10]
        assert subroutine.name == "panic_unwind::real_imp::find_eh_action::{closure#0}"
        # item with tracked namespace
        subroutine = elf.functions_debug_info[0x0003FBF0]
        assert subroutine.name == "panic_unwind::real_imp::panic::exception_cleanup"

        # item with inlined functions
        subroutine = elf.functions_debug_info[0x0003FC30]
        assert len(subroutine.inlined_functions) == 1
        inlined = subroutine.inlined_functions[0]
        assert inlined.name == "panic_unwind::real_imp::rust_eh_personality_impl"
        assert inlined.ranges == [(0x3FC49, 0x3FEA6), (0x3FEC4, 0x3FEE8)]
        assert inlined.low_pc == 0x3FC49
        assert inlined.high_pc == 0x3FEE8

        # item with multiple nested inlined functions - we only care about the outer ones for now
        subroutine = elf.functions_debug_info[0x000527E0]
        assert len(subroutine.inlined_functions) == 1


if __name__ == "__main__":
    main()
