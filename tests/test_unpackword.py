from __future__ import annotations

from io import BytesIO

import archinfo
import pytest

import cle


def test_unpackword():
    # Make sure the base address behaves as expected regardless of whether offset is specified or not.

    BASE_ADDR = 0x8000000
    ENTRYPOINT = 0x8000000

    blob = BytesIO(
        b"\x37\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        b"\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
    )
    ld = cle.Loader(
        blob,
        main_opts={
            "backend": "blob",
            "base_addr": BASE_ADDR,
            "entry_point": ENTRYPOINT,
            "arch": "x86",
            "offset": 0,
        },
        auto_load_libs=True,
    )

    # little endian
    byt = ld.memory.unpack_word(BASE_ADDR, 1)
    assert byt == 0x37
    short = ld.memory.unpack_word(BASE_ADDR, 2)
    assert short == 0x0137
    long = ld.memory.unpack_word(BASE_ADDR, 4)
    assert long == 0x03020137
    quad = ld.memory.unpack_word(BASE_ADDR, 8)
    assert quad == 0x0706050403020137
    xmmword = ld.memory.unpack_word(BASE_ADDR, 16)
    assert xmmword == 0x0F0E0D0C0B0A09080706050403020137

    # big endian
    byt = ld.memory.unpack_word(BASE_ADDR, 1, endness=archinfo.Endness.BE)
    assert byt == 0x37
    short = ld.memory.unpack_word(BASE_ADDR, 2, endness=archinfo.Endness.BE)
    assert short == 0x3701
    long = ld.memory.unpack_word(BASE_ADDR, 4, endness=archinfo.Endness.BE)
    assert long == 0x37010203
    quad = ld.memory.unpack_word(BASE_ADDR, 8, endness=archinfo.Endness.BE)
    assert quad == 0x3701020304050607
    xmmword = ld.memory.unpack_word(BASE_ADDR, 16, endness=archinfo.Endness.BE)
    assert xmmword == 0x370102030405060708090A0B0C0D0E0F

    # signed xmmword
    xmmword = ld.memory.unpack_word(BASE_ADDR + 16, 16, endness=archinfo.Endness.BE, signed=True)
    assert xmmword == 0xFDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE - 2**128
    xmmword = ld.memory.unpack_word(BASE_ADDR + 16, 16, endness=archinfo.Endness.LE, signed=True)
    assert xmmword == 0xFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD - 2**128

    # ymmword
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.BE, signed=False)
    assert ymmword == 0x370102030405060708090A0B0C0D0E0FFDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.BE, signed=True)
    assert ymmword == 0x370102030405060708090A0B0C0D0E0FFDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.LE, signed=False)
    assert ymmword == 0xFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD0F0E0D0C0B0A09080706050403020137
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.LE, signed=True)
    assert ymmword == 0xFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD0F0E0D0C0B0A09080706050403020137 - 2**256


def test_word_sizes_struct_cannot_express():
    # struct has integer format characters for 1, 2, 4 and 8 bytes only. Every other width - the
    # 3-byte word of a 24-bit architecture among them - is composed from its bytes.
    clemory = cle.Clemory(archinfo.ArchX86(), root=True)
    clemory.add_backer(0, bytes(32))

    clemory.pack_word(0, 0x123456, size=3)
    assert clemory.load(0, 4) == b"\x56\x34\x12\x00"
    assert clemory.unpack_word(0, 3) == 0x123456

    clemory.pack_word(4, 0x123456, size=3, endness=archinfo.Endness.BE)
    assert clemory.load(4, 3) == b"\x12\x34\x56"
    assert clemory.unpack_word(4, 3, endness=archinfo.Endness.BE) == 0x123456

    clemory.pack_word(8, -2, size=3, signed=True)
    assert clemory.load(8, 3) == b"\xfe\xff\xff"
    assert clemory.unpack_word(8, 3, signed=True) == -2
    assert clemory.unpack_word(8, 3) == 0xFFFFFE

    # the same goes for anything wider than 8 bytes, power of two or not
    clemory.pack_word(12, 0x0102030405060708090A, size=10)
    assert clemory.unpack_word(12, 10) == 0x0102030405060708090A
    clemory.pack_word(12, 0x0102030405060708090A0B0C0D0E0F10, size=16)
    assert clemory.unpack_word(12, 16) == 0x0102030405060708090A0B0C0D0E0F10


def test_word_off_the_end_of_a_backer():
    clemory = cle.Clemory(archinfo.ArchX86(), root=True)
    clemory.add_backer(0, bytes(2))

    with pytest.raises(KeyError):
        clemory.unpack_word(0, 3)

    # a write that does not fit leaves memory alone rather than storing the bytes that do fit
    with pytest.raises(KeyError):
        clemory.pack_word(0, 0x123456, size=3)
    assert clemory.load(0, 2) == b"\x00\x00"


if __name__ == "__main__":
    test_unpackword()
    test_word_sizes_struct_cannot_express()
    test_word_off_the_end_of_a_backer()
