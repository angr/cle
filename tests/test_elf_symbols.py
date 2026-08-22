#!/usr/bin/env python
from __future__ import annotations

import io
import os
import struct

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import cle
from cle.backends.elf.symbol import ELFSymbol

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

# The index gcc -mcmodel=medium gives a common symbol too large for the small code model.
SHN_X86_64_LCOMMON = 0xFF02


def _retag_symbol(image, name, st_shndx):
    """Return *image* with the st_shndx of every symbol table entry named *name* rewritten."""
    data = bytearray(image)
    for section in ELFFile(io.BytesIO(image)).iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for index, symbol in enumerate(section.iter_symbols()):
            if symbol.name == name:
                # Elf64_Sym: st_name (4 bytes), st_info (1), st_other (1), st_shndx (2), ...
                struct.pack_into("<H", data, section["sh_offset"] + index * section["sh_entsize"] + 6, st_shndx)
    return bytes(data)


def _ofname_symbol(image):
    """Load the object *image* and return its ofname symbol."""
    ld = cle.Loader(io.BytesIO(image), auto_load_libs=False)
    assert isinstance(ld.main_object, cle.ELF)
    assert ld.main_object.is_relocatable
    symbol = ld.main_object.get_symbol("ofname")
    assert isinstance(symbol, ELFSymbol)
    return symbol


def test_large_common_symbol():
    """
    An st_shndx from SHN_LORESERVE up is a tag, not a section header table index.

    gzip.o has ofname as an ordinary SHN_COMMON symbol; retagging it SHN_X86_64_LCOMMON is what the
    compiler does for a common symbol that does not fit the small code model.
    """
    with open(os.path.join(TESTS_BASE, "x86_64", "decompiler", "gzip.o"), "rb") as f:
        image = f.read()

    common = _ofname_symbol(image)
    assert common.is_common
    assert common.section is None
    assert common.is_export

    large = _ofname_symbol(_retag_symbol(image, "ofname", SHN_X86_64_LCOMMON))
    # The tag names no section, so the symbol gets none and no section remap offset either.
    assert large.section is None
    assert large.relative_addr == common.relative_addr
    # It still defines ofname for anything linking against this object.
    assert large.is_export


if __name__ == "__main__":
    test_large_common_symbol()
