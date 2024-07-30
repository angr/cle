from __future__ import annotations

import logging
import os
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


@unittest.skipIf(cle.backends.xbe.Xbe is None, "pyxbe not available")
def test_xbe():
    xbe = os.path.join(TEST_BASE, "tests", "x86", "xbox", "triangle.xbe")
    ld = cle.Loader(xbe, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.XBE)
    assert ld.main_object.os == "xbox"
    assert ld.main_object.mapped_base == 0x10000
    assert sorted([sec.name for sec in ld.main_object.sections]) == sorted(
        [
            ".rdata",
            ".bss",
            ".data",
            ".text",
            ".tls",
            ".idata",
            ".reloc",
        ]
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_xbe()
