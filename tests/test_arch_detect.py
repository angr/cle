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
from cle.backends.elf.elf import ELF

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

    def test_elf_nds32(self):
        binpath = os.path.join(test_location, "nds32/crt0_nds32le.o")
        ld = cle.Loader(binpath, auto_load_libs=False)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "NDS32:LE:32:default"

    def test_elf_hppa(self):
        # The only ELF opinion for EM_PARISC applies to e_flags 528, which this file has.
        binpath = os.path.join(test_location, "hppa/test-instr_hppa")
        ld = cle.Loader(binpath, auto_load_libs=False)
        arch = ld.main_object.arch
        assert isinstance(arch, archinfo.ArchPcode)
        assert arch.name == "pa-risc:BE:32:default"

    def test_opinion_secondary_forms(self):
        # The three forms the shipped opinions write e_flags in: decimal for PA-RISC,
        # hexadecimal for MSP430X, and a bit pattern with free bits for LoongArch lp64d.
        matches = ELF._pcode_secondary_matches
        assert matches("528", 0x210)
        assert not matches("528", 0x214)
        assert matches("0x2d", 0x2D)
        assert not matches("0x2d", 0)
        assert matches("0b .... .... .... .... .... .... .... .011", 0x43)
        assert not matches("0b .... .... .... .... .... .... .... .011", 0x42)
        assert not matches("golang", 0)


if __name__ == "__main__":
    unittest.main()
