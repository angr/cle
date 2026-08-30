from __future__ import annotations

import os
import unittest

import cle
from cle.backends.elf.relocation.ppc64 import R_PPC64_JMP_SLOT
from cle.backends.symbol import SymbolType

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_f_finale_extern_size_hints():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "f_finale.o")
    ld = cle.Loader(path, auto_load_libs=False)
    obj = ld.main_object

    assert obj.is_relocatable  # type: ignore[attr-defined]
    assert hasattr(obj, "extern_size_hints")

    # mobjinfo: max addend is 52
    # min_size = 52 + 8 = 60
    assert obj.extern_size_hints["mobjinfo"] == 60  # type: ignore[attr-defined]

    mobjinfo = None
    for sym in ld.symbols:
        if sym.is_extern and sym.name == "mobjinfo":
            mobjinfo = sym
            break

    assert mobjinfo is not None
    assert mobjinfo.size == 60

    # Find the next symbol after mobjinfo
    next_sym = None
    for sym in ld.symbols:
        if sym.is_extern and sym.rebased_addr > mobjinfo.rebased_addr:
            if next_sym is None or sym.rebased_addr < next_sym.rebased_addr:
                next_sym = sym

    # Verify no overlap: mobjinfo end <= next symbol start
    assert next_sym is not None
    assert mobjinfo.rebased_addr + mobjinfo.size <= next_sym.rebased_addr


def test_ppc64_abiv1_untyped_function_import():
    """An imported function left STT_NOTYPE still needs an ELFv1 function descriptor.

    A jump slot on PowerPC64 ELFv1 holds a whole descriptor rather than an address, so an
    unresolved import needs one however the symbol table typed it. Deciding that from the
    declared type gives an untyped import a pointer-sized slot instead, and the descriptor copy
    then reads past it.
    """
    pristine = os.path.join(TESTS_BASE, "tests", "ppc64", "fauxware")
    untyped = os.path.join(TESTS_BASE, "tests", "ppc64", "fauxware_notype_import")

    def jump_slots(path):
        """The object, and each of its jump slots paired with the symbol it names."""
        obj = cle.Loader(path, auto_load_libs=False).main_object
        slots = []
        for reloc in obj.relocs:
            symbol = reloc.symbol
            if isinstance(reloc, R_PPC64_JMP_SLOT) and symbol is not None:
                slots.append((symbol, reloc))
        return obj, slots

    def descriptors(path):
        obj, slots = jump_slots(path)
        return {
            symbol.name: tuple(obj.memory.unpack_word(reloc.relative_addr + offset) for offset in (0, 8, 16))
            for symbol, reloc in slots
        }

    # the derived fixture has to still carry the shape, or this test proves nothing
    _, slots = jump_slots(untyped)
    assert {s.name for s, _ in slots if s.type is not SymbolType.TYPE_FUNCTION} == {"puts", "exit"}

    expected = descriptors(pristine)
    assert expected, "the pristine fixture has no jump slots to compare"
    assert descriptors(untyped) == expected


if __name__ == "__main__":
    unittest.main()
