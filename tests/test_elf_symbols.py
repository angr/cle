#!/usr/bin/env python
from __future__ import annotations

import os

import cle
from cle.backends.elf.symbol import ELFSymbol

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_large_common_symbol():
    """
    An st_shndx from SHN_LORESERVE up is a tag, not a section header table index.

    large_common.o is built with -mcmodel=medium, which puts a common symbol too large for the small
    code model at SHN_X86_64_LCOMMON (0xFF02) instead of SHN_COMMON. Subscripting the section list
    with that used to raise IndexError before the object finished loading.
    """
    ld = cle.Loader(os.path.join(TESTS_BASE, "x86_64", "large_common.o"), auto_load_libs=False)
    assert isinstance(ld.main_object, cle.ELF)
    assert ld.main_object.is_relocatable

    symbol = ld.main_object.get_symbol("big_buffer")
    assert isinstance(symbol, ELFSymbol)
    # The tag names no section, so the symbol gets none and no section remap offset either.
    assert symbol.section is None
    assert not symbol.is_common
    # It still defines big_buffer for anything linking against this object.
    assert symbol.is_export


def test_common_symbol():
    """An ordinary SHN_COMMON symbol keeps naming no section, and stays an export."""
    ld = cle.Loader(os.path.join(TESTS_BASE, "x86_64", "decompiler", "gzip.o"), auto_load_libs=False)
    symbol = ld.main_object.get_symbol("ofname")
    assert isinstance(symbol, ELFSymbol)
    assert symbol.is_common
    assert symbol.section is None
    assert symbol.is_export


if __name__ == "__main__":
    test_large_common_symbol()
    test_common_symbol()
