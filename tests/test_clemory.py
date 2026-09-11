from __future__ import annotations

import struct
import sys
import timeit
import unittest

import cffi
import pytest

import cle


@unittest.skipIf(sys.platform == "emscripten", "runtime CFFI compilation is unavailable in Pyodide")
def test_cclemory():  # pylint: disable=no-member
    # This is a test case for C-backed Clemory.

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"\x90" * 1000)
    clemory.add_backer(2000, b"A" * 1000)
    clemory.add_backer(3000, b"ABCDEFGH")

    ffi = cffi.FFI()
    ffi.cdef("""
        int memcmp(const void* s1, const void* s2, size_t n);
    """)
    c = ffi.verify("""
        #include <string.h>
    """)
    bytes_c = [ffi.from_buffer(backer) for _, backer in clemory.backers()]
    assert len(bytes_c) == 3
    out = c.memcmp(ffi.new("unsigned char []", b"\x90" * 10), bytes_c[0], 10)
    assert out == 0

    out = c.memcmp(ffi.new("unsigned char []", b"B" * 1000), bytes_c[1], 1000)
    assert out != 0
    out = c.memcmp(ffi.new("unsigned char []", b"A" * 1000), bytes_c[1], 1000)
    assert out == 0

    out = c.memcmp(ffi.new("unsigned char []", b"ABCDEFGH"), bytes_c[2], 8)
    assert out == 0


def test_clemory():
    # directly write bytes to backers
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"A" * 20)
    clemory.add_backer(20, b"A" * 20)
    clemory.add_backer(50, b"A" * 20)
    assert len(clemory._backers) == 3

    clemory.store(10, b"B" * 30)

    assert len(clemory._backers) == 3
    assert clemory.load(0, 40) == b"A" * 10 + b"B" * 30

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(10, b"A" * 20)
    clemory.add_backer(50, b"A" * 20)
    assert len(clemory._backers) == 2
    try:
        clemory.store(0, b"")
    except KeyError:
        assert True
    else:
        assert False
    assert len(clemory._backers) == 2
    try:
        clemory.load(0, 25)
    except KeyError:
        assert True
    else:
        assert False
    clemory.seek(0)
    assert clemory.read(25) == b""
    assert clemory.load(10, 25) == b"A" * 20


def performance_clemory_contains():
    # With the consecutive optimization:
    #   5.72 sec
    # Without the consecutive optimization:
    #   13.11 sec
    t = timeit.timeit(
        "0x400002 in clemory",
        setup="import cle; clemory = cle.Clemory(None, root=True); clemory.add_backer(0x400000, 'A' * 200000)",
        number=20000000,
    )
    print(t)


def test_clemory_contains():
    clemory = cle.Clemory(None, root=True)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 0
    assert clemory.consecutive is True

    # Add one backer
    clemory.add_backer(0, b"A" * 10)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 10
    assert clemory.consecutive is True

    # Add another backer
    clemory.add_backer(10, b"B" * 20)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 30
    assert clemory.consecutive is True

    # Add one more
    clemory.add_backer(40, b"A" * 30)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 70
    assert clemory.consecutive is False

    # Add another one to make it consecutive
    clemory.add_backer(30, b"C" * 10)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 70
    assert clemory.consecutive is True


def test_clemory_malformed_format():
    # a format string struct cannot parse is a format error, not an out-of-bounds access, and
    # classifying it must not raise struct.error out of the handler doing the classification
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"A" * 4)

    with pytest.raises(struct.error) as excinfo:
        clemory.unpack(0, "<Z")
    assert excinfo.value.__context__ is None

    with pytest.raises(struct.error) as excinfo:
        clemory.pack(0, "<Z", 1)
    assert excinfo.value.__context__ is None

    # a format struct can parse that runs off the end of the backer is still a KeyError
    with pytest.raises(KeyError):
        clemory.unpack(2, "<I")
    with pytest.raises(KeyError):
        clemory.pack(2, "<I", 1)


def test_clemory_read_only_view_malformed_format():
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"A" * 4)
    view = cle.ClemoryReadOnlyView(None, clemory)

    with pytest.raises(struct.error) as excinfo:
        view.unpack(0, "<Z")
    assert excinfo.value.__context__ is None
    with pytest.raises(KeyError):
        view.unpack(2, "<I")

    # and again now that the backer the reads above found is cached, which is a separate handler
    assert view.unpack(0, "<H") == (0x4141,)
    with pytest.raises(struct.error) as excinfo:
        view.unpack(0, "<Z")
    assert excinfo.value.__context__ is None
    with pytest.raises(KeyError):
        view.unpack(2, "<I")


def main():
    g = globals()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()


if __name__ == "__main__":
    main()
