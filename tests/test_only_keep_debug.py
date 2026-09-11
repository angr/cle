# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
import unittest

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


def load(*path: str, **kwargs) -> cle.backends.ELF:
    elf = cle.Loader(os.path.join(TESTS_BASE, *path), auto_load_libs=False, **kwargs).main_object
    assert isinstance(elf, cle.backends.ELF)
    return elf


class TestOnlyKeepDebug(unittest.TestCase):
    def test_dynamic_table_without_contents(self):
        # linked_list.debug is the objcopy --only-keep-debug output of linked_list, the kind of file
        # /usr/lib/debug and -dbg packages are made of. Every allocated section is SHT_NOBITS, so its
        # dynamic table has neither contents in the file nor anything behind it in the loaded image.
        elf = load("x86_64", "linked_list.debug")

        # nothing is left of the dynamic table or the dynamic symbols
        assert elf.deps == []
        assert elf.get_symbol("printf") is None

        # but the retained .symtab is still read
        main = elf.get_symbol("main")
        assert main is not None
        assert main.rebased_addr == 0x4005E9

    def test_debug_info_is_preserved(self):
        # the reason to load one of these files at all: it carries the debug info of the binary it was split from
        stock = load("x86_64", "linked_list", load_debug_info=True)
        debug = load("x86_64", "linked_list.debug", load_debug_info=True)

        subprograms = {addr: subprogram.name for addr, subprogram in debug.functions_debug_info.items()}
        assert subprograms == {addr: subprogram.name for addr, subprogram in stock.functions_debug_info.items()}
        assert subprograms == {0x40057D: "sum", 0x4005B7: "alloc", 0x4005E9: "main"}
        assert dict(stock.addr_to_line)
        assert dict(debug.addr_to_line) == dict(stock.addr_to_line)

    def test_dynamic_table_filesz_zero(self):
        # fauxware_dynamic_filesz0 is fauxware with p_filesz cleared on PT_DYNAMIC alone, leaving the
        # segment that carries the dynamic table backed by the file. Its dynamic table still has to be read.
        elf = load("x86_64", "fauxware_dynamic_filesz0")

        assert elf.deps == ["libc.so.6"]
        puts = elf.get_symbol("puts")
        assert puts is not None
        assert puts.is_import


if __name__ == "__main__":
    unittest.main()
