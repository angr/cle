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

    def test_elf_x32(self):
        # The x32 ABI puts x86-64 code in an ELFCLASS32 container: the class gives the pointer width
        # and the machine gives the instruction set. Resolving by the class alone picks 32-bit X86,
        # and none of the instruction stream decodes.
        path = os.path.join(test_location, "x86_64", "x32_relocatable.o")
        ld = cle.Loader(path, main_opts={"backend": "elf"}, auto_load_libs=False)

        assert isinstance(ld.main_object.arch, archinfo.ArchAMD64)

    def test_elf_m68k(self):
        binpath = os.path.join(test_location, "m68k/mul_add_sub_xor_m68k_be")
        ld = cle.Loader(binpath, auto_load_libs=True)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "68000:BE:32:default"


if __name__ == "__main__":
    unittest.main()
