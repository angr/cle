
import nose
from io import BytesIO

import archinfo
import cle


def test_unpackword():
    # Make sure the base address behaves as expected regardless of whether offset is specified or not.

    BASE_ADDR = 0x8000000
    ENTRYPOINT = 0x8000000

    blob = BytesIO(b"\x37\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                   b"\xfd\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe")
    ld = cle.Loader(blob, main_opts={
        'backend': 'blob',
        'base_addr': BASE_ADDR,
        'entry_point': ENTRYPOINT,
        'arch': "x86",
        'offset': 0,
    })

    # little endian
    byt = ld.memory.unpack_word(BASE_ADDR, 1)
    nose.tools.assert_equal(byt, 0x37)
    short = ld.memory.unpack_word(BASE_ADDR, 2)
    nose.tools.assert_equal(short, 0x0137)
    long = ld.memory.unpack_word(BASE_ADDR, 4)
    nose.tools.assert_equal(long, 0x03020137)
    quad = ld.memory.unpack_word(BASE_ADDR, 8)
    nose.tools.assert_equal(quad, 0x0706050403020137)
    xmmword = ld.memory.unpack_word(BASE_ADDR, 16)
    nose.tools.assert_equal(xmmword, 0x0f0e0d0c0b0a09080706050403020137)

    # big endian
    byt = ld.memory.unpack_word(BASE_ADDR, 1, endness=archinfo.Endness.BE)
    nose.tools.assert_equal(byt, 0x37)
    short = ld.memory.unpack_word(BASE_ADDR, 2, endness=archinfo.Endness.BE)
    nose.tools.assert_equal(short, 0x3701)
    long = ld.memory.unpack_word(BASE_ADDR, 4, endness=archinfo.Endness.BE)
    nose.tools.assert_equal(long, 0x37010203)
    quad = ld.memory.unpack_word(BASE_ADDR, 8, endness=archinfo.Endness.BE)
    nose.tools.assert_equal(quad, 0x3701020304050607)
    xmmword = ld.memory.unpack_word(BASE_ADDR, 16, endness=archinfo.Endness.BE)
    nose.tools.assert_equal(xmmword, 0x370102030405060708090a0b0c0d0e0f)

    # signed xmmword
    xmmword = ld.memory.unpack_word(BASE_ADDR + 16, 16, endness=archinfo.Endness.BE, signed=True)
    nose.tools.assert_equal(xmmword, 0xfdfffffffffffffffffffffffffffffe - 2**128)
    xmmword = ld.memory.unpack_word(BASE_ADDR + 16, 16, endness=archinfo.Endness.LE, signed=True)
    nose.tools.assert_equal(xmmword, 0xfefffffffffffffffffffffffffffffd - 2**128)

    # ymmword
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.BE, signed=False)
    nose.tools.assert_equal(ymmword, 0x370102030405060708090a0b0c0d0e0ffdfffffffffffffffffffffffffffffe)
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.BE, signed=True)
    nose.tools.assert_equal(ymmword, 0x370102030405060708090a0b0c0d0e0ffdfffffffffffffffffffffffffffffe)
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.LE, signed=False)
    nose.tools.assert_equal(ymmword, 0xfefffffffffffffffffffffffffffffd0f0e0d0c0b0a09080706050403020137)
    ymmword = ld.memory.unpack_word(BASE_ADDR, 32, endness=archinfo.Endness.LE, signed=True)
    nose.tools.assert_equal(ymmword, 0xfefffffffffffffffffffffffffffffd0f0e0d0c0b0a09080706050403020137 - 2**256)


if __name__ == "__main__":
    test_unpackword()
