# pylint: disable=missing-class-docstring
from __future__ import annotations

import binascii
import os
import unittest

import cle

TEST_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
    os.path.join("mips", "mips-hilo.o"),
)


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

        ld = cle.Loader(TEST_FILE, auto_load_libs=False, main_opts={"base_addr": 0x21000})
        assert EXPECTED_RESULT == binascii.hexlify(ld.memory.load(0x21000, 0x1C))


if __name__ == "__main__":
    unittest.main()
