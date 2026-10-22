# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main
from unittest.mock import Mock

from elftools.construct import Container

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestDwarf(TestCase):
    def test_line_program_file_indices(self):
        cases = (
            (4, (1, 2), [b"include"], "/build/main.c", "/build/include/header.h"),
            (5, (0, 1), [b"source", b"include"], "/build/source/main.c", "/build/include/header.h"),
            (5, (0, 1), [b"/source", b"/include"], "/source/main.c", "/include/header.h"),
        )
        for version, files, directories, main_path, header_path in cases:
            with self.subTest(version=version, directories=directories):
                cu = Mock()
                cu.get_top_DIE.return_value.attributes = {"DW_AT_comp_dir": Container(value=b"/build")}
                lineprog = Mock()
                lineprog.header = Container(
                    version=version,
                    file_entry=[Container(name=b"main.c", dir_index=0), Container(name=b"header.h", dir_index=1)],
                    include_directory=directories,
                )
                lineprog.get_entries.return_value = [Container(state=None)] + [
                    Container(state=Container(address=addr, file=file, line=line))
                    for addr, file, line in ((0x1010, files[0], 11), (0x1011, files[1], 23), (0x1012, files[0], 12))
                ]
                dwarf = Mock()
                dwarf.iter_CUs.return_value = [cu]
                dwarf.line_program_for_CU.return_value = lineprog
                elf = cle.backends.ELF.__new__(cle.backends.ELF)
                elf.linked_base = 0x1000
                elf.mapped_base = 0x4000
                elf.addr_to_line = {}
                elf._load_line_info(dwarf)
                assert elf.addr_to_line == {
                    0x4010: {(main_path, 11)},
                    0x4011: {(header_path, 23)},
                    0x4012: {(main_path, 12)},
                }

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
