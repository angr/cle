# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main

import cle
from cle.backends.elf.hashtable import GNUHashTable

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestELFHashTable(TestCase):
    """
    A hash table's whole job is to find the symbols that are in it.

    A GNU hash table covers the symbols from ``symndx`` up; the ones below it are the imports,
    which are deliberately not hashed. So every symbol at or above ``symndx`` has to come back
    from a lookup by its own name, whatever byte order the file is written in.
    """

    def _unfindable(self, arch, name):
        loader = cle.Loader(os.path.join(TESTS_BASE, arch, name), auto_load_libs=False)
        assert isinstance(loader.main_object, cle.ELF)
        table = loader.main_object.hashtable
        assert isinstance(table, GNUHashTable)
        symtab = table.symtab
        missing = []
        for i in range(table.symndx, symtab.num_symbols()):
            symbol_name = symtab.get_symbol(i).name
            if symbol_name and table.get(symbol_name)[1] is None:
                missing.append(symbol_name)
        return missing

    def test_big_endian_32(self):
        self.assertEqual(self._unfindable("ppc", "libc.so.6"), [])

    def test_big_endian_64(self):
        self.assertEqual(self._unfindable("ppc64", "libc.so.6"), [])

    def test_little_endian_64(self):
        self.assertEqual(self._unfindable("x86_64", "libc.so.6"), [])


if __name__ == "__main__":
    main()
