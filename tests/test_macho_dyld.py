import os
from typing import cast

import nose

import angr
import cle
from cle import MachO

from pathlib import Path
TEST_BASE = Path(__file__).resolve().parent.parent.parent / "binaries"


def test_rebases():
    binary: MachO = cast(MachO, cle.Loader(str(TEST_BASE / "tests" / "aarch64" / "dyld_ios15.macho")).main_object)
    expected = {0x100008100: 0x100007a40,
                0x1000081e0: 0x1000072b0,
                0x1000081e8: 0x1000072dc,
                0x1000081f0: 0x1000072e4,
                0x1000081f8: 0x100007310,
                0x100008200: 0x100007350,
                0x100008208: 0x10000735c,
                0x100008210: 0x10000738c,
                0x100008218: 0x1000073e8,
                0x100008238: 0x1000081e0,
                0x100008248: 0x100007a40,
                0x1000082a0: 0x100007afc,
                0x1000082d8: 0x10000c0e8,
                0x10000c018: 0x100007b90,
                0x10000c060: 0x100007b90,
                0x10000c068: 0x100007998,
                0x10000c090: 0x100007c2a,
                0x10000c0d0: 0x10000c000,
                0x10000c0d8: 0x100007210,
                0x10000c0e8: 0x10000c0b0,
                0x10000c108: 0x10000c04a,
                0x10000c128: 0x1000079f0}
    nose.tools.assert_dict_equal(binary._dyld_rebases, expected)

if __name__ == '__main__':
    test_rebases()
