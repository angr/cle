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
        ld = cle.Loader(binpath, auto_load_libs=True)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "68000:BE:32:default"


class TestArmArchDetect(unittest.TestCase):
    """
    Test ARM architecture detection, including the BE8 instruction/data endianness split.
    """

    @unittest.skipIf(pypcode is None, "pypcode not installed")
    def test_elf_arm_be8(self):
        binpath = os.path.join(test_location, "armeb/be8_loop")
        arch = cle.Loader(binpath, auto_load_libs=False).main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "ARM:LEBE:32:v7LEInstruction"
        assert arch.memory_endness == archinfo.Endness.BE

    def test_elf_arm_be32(self):
        binpath = os.path.join(test_location, "armeb/be32_loop")
        arch = cle.Loader(binpath, auto_load_libs=False).main_object.arch
        assert arch.name == "ARMHF"
        assert arch.memory_endness == archinfo.Endness.BE
        assert arch.instruction_endness == archinfo.Endness.BE

    def test_elf_armhf_le(self):
        binpath = os.path.join(test_location, "armhf/fauxware")
        arch = cle.Loader(binpath, auto_load_libs=False).main_object.arch
        assert arch.name == "ARMHF"
        assert arch.memory_endness == archinfo.Endness.LE

    def test_elf_armel_le(self):
        binpath = os.path.join(test_location, "armel/test_arrays")
        arch = cle.Loader(binpath, auto_load_libs=False).main_object.arch
        assert arch.name == "ARMEL"
        assert arch.memory_endness == archinfo.Endness.LE


if __name__ == "__main__":
    unittest.main()
