# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestElfResiliency(TestCase):
    def test_malformed_section_keeps_the_rest_of_the_table(self):
        """
        A section whose sh_link points at nothing must not cost us the rest of the section header table.

        u-boot's linker scripts discard .dynstr while keeping .hash and .dynsym, so the linker writes sh_link = 0
        into both and pyelftools refuses to build them. CLE used to answer that by discarding the whole section
        header table and rereading the file from the program headers, which threw away .symtab as well and left
        the binary with no symbols at all. The fixture has the same section table, built by clang and GNU ld.
        """
        binary_path = os.path.join(TESTS_BASE, "i386", "hash_without_dynstr")
        obj = cle.Loader(binary_path, auto_load_libs=False).main_object

        assert ".symtab" in {section.name for section in obj.sections}
        # These functions are only reachable through a table of pointers, so their symbols are all we have.
        names = {symbol.name for symbol in obj.symbols if symbol.is_function}
        assert {"table_helper", "table_entry_one", "table_entry_two"} <= names


if __name__ == "__main__":
    main()
