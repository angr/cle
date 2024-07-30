from __future__ import annotations

from io import BytesIO

import archinfo

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


if __name__ == "__main__":
    test_unpackword()
