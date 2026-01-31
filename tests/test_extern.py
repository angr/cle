from __future__ import annotations

import os
import unittest

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_f_finale_extern_size_hints():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "f_finale.o")
    ld = cle.Loader(path, auto_load_libs=False)
    obj = ld.main_object

    assert obj.is_relocatable
    assert hasattr(obj, "extern_size_hints")

    # mobjinfo: max addend is 52
    # min_size = 52 + 8 = 60
    assert obj.extern_size_hints["mobjinfo"] == 60

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


if __name__ == "__main__":
    unittest.main()
