# pylint:disable=no-self-use
from __future__ import annotations

import os
import unittest

import archinfo

try:
    import pypcode
except ImportError:
    pypcode = None

import cle

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))


@unittest.skipIf(pypcode is None, "pypcode not installed")
class TestArchPcodeDetect(unittest.TestCase):
    """
    Test architecture detection.
    """

    def test_elf_m68k(self):
        binpath = os.path.join(test_location, "m68k/mul_add_sub_xor_m68k_be")
        ld = cle.Loader(binpath)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "68000:BE:32:default"


if __name__ == "__main__":
    unittest.main()
