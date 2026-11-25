# pylint: disable=missing-class-docstring
from __future__ import annotations

import binascii
import os
import unittest
from ctypes import c_int16

import cle

TEST_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)

REL_FILE = os.path.join(TEST_DIR, "mips", "mips-hilo.o")

# One assembly source built for three ABIs, so the same five relocations appear as Elf64_Rela,
# Elf32_Rela and Elf32_Rel. Each object holds two matched %hi/%lo pairs and a trailing %hi whose
# %lo never follows it. See tests_src/relocs/mips in angr/binaries.
RELA_FILE = os.path.join(TEST_DIR, "mips64", "mips64-hilo-rela.o")
RELA_N32_FILE = os.path.join(TEST_DIR, "mips64", "mipsn32-hilo-rela.o")
REL_UNPAIRED_FILE = os.path.join(TEST_DIR, "mips", "mips-hilo-unpaired.o")

BASE_ADDR = 0x21000

# Loaded at BASE_ADDR those three objects put .data at 0x21020 and .bss at 0x21030, which makes
# the addresses their relocations build 0x21020, 0x29030 and 0x2d034:
#
# 0x21000:      R_MIPS_HI16     3c080002        lui     $8, 2               %hi(0x21020)
# 0x21004:      R_MIPS_LO16     8d091020        lw      $9, 4128($8)        %lo(0x21020)
# 0x21008:      R_MIPS_HI16     3c0a0003        lui     $10, 3              %hi(0x29030)
# 0x2100c:      R_MIPS_LO16     8d4b9030        lw      $11, -28624($10)    %lo(0x29030)
# 0x21010:      R_MIPS_HI16     3c0c0003        lui     $12, 3              %hi(0x2d034)
#
# The second pair sits 0x8000 past its section symbol, so its low halfword is negative once
# sign-extended and the lui has to load one more than the plain high half to compensate.
RELA_EXPECTED_RESULT = b"3c0800028d0910203c0a00038d4b90303c0c0003"

# The (lui, lw) offsets of the pairs above, and the addresses they build.
HILO_PAIRS = ((0x00, 0x04, 0x21020), (0x08, 0x0C, 0x29030))

# The trailing R_MIPS_HI16 of the SHT_REL object keeps the immediate the assembler left in it,
# since a REL addend is split across the pair and half of it is missing.
REL_UNPAIRED_EXPECTED_RESULT = b"3c0800028d0910203c0a00038d4b90303c0c0001"


def _computed_address(loader, hi_addr, lo_addr):
    """
    The address the lui/lw pair at these addresses builds at run time: the halfword the lui
    loads, plus the sign-extended immediate the lw adds to it. Both objects are big-endian, so
    the immediate field is the second halfword of the instruction.
    """
    high = loader.memory.unpack_word(hi_addr + 2, size=2)
    low = loader.memory.unpack_word(lo_addr + 2, size=2)
    return ((high << 16) + c_int16(low).value) & 0xFFFFFFFF


class TestMipsRellocations(unittest.TestCase):

    @staticmethod
    def test_mips_hilo16():
        # 0x21000:        R_MIPS_HI16     3c080002        lui     $t0, 2
        # 0x21004:        R_MIPS_HI16     3c090002        lui     $t1, 2
        # 0x21008:        R_MIPS_LO16     21081004        addi    $t0, $t0, 4100
        # 0x2100c:        R_MIPS_LO16     2108102c        addi    $t0, $t0, 4140
        # 0x21010:        R_MIPS_HI16     3c080003        lui     $t0, 3
        # 0x21014:        R_MIPS_HI16     3c090004        lui     $t1, 4
        # 0x21018:        R_MIPS_LO16     2108101c        addi    $t0, $t0, 4124
        EXPECTED_RESULT = b"3c0800023c090002210810042108102c3c0800033c0900042108101c"

        ld = cle.Loader(REL_FILE, auto_load_libs=False, main_opts={"base_addr": 0x21000})
        assert EXPECTED_RESULT == binascii.hexlify(ld.memory.load(0x21000, 0x1C))

    def test_mips_hilo16_rela(self):
        for path in (RELA_FILE, RELA_N32_FILE):
            with self.subTest(path=os.path.basename(path)):
                ld = cle.Loader(path, auto_load_libs=False, main_opts={"base_addr": BASE_ADDR})
                assert RELA_EXPECTED_RESULT == binascii.hexlify(ld.memory.load(BASE_ADDR, 0x14))
                for hi_offset, lo_offset, address in HILO_PAIRS:
                    assert _computed_address(ld, BASE_ADDR + hi_offset, BASE_ADDR + lo_offset) == address
                # One of those addresses has to need the carry, or the pair below stops covering it.
                assert any(address & 0x8000 for _, _, address in HILO_PAIRS)

    def test_mips_hi16_without_lo16(self):
        with self.assertLogs("cle.backends.elf.relocation.mips", level="WARNING") as logs:
            ld = cle.Loader(REL_UNPAIRED_FILE, auto_load_libs=False, main_opts={"base_addr": BASE_ADDR})
        assert REL_UNPAIRED_EXPECTED_RESULT == binascii.hexlify(ld.memory.load(BASE_ADDR, 0x14))
        assert len(logs.records) == 1
        # The warning names the one R_MIPS_HI16 that has no partner, not some other relocation.
        assert logs.records[0].getMessage().endswith(hex(BASE_ADDR + 0x10))


if __name__ == "__main__":
    unittest.main()
