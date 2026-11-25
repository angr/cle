from __future__ import annotations

import os
import sys
import timeit
import unittest

import cffi

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


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


def test_clemory_read_only_view_contains():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    loader.gen_ro_memview()
    view = loader.memory_ro_view
    assert view is not None

    entry = loader.main_object.entry
    assert entry in view
    assert entry - 0x10000 not in view

    # The view answers the same as the clemory it was flattened from, including in the gaps
    # between backers.
    for start, backer in loader.memory.backers():
        for addr in (start - 1, start, start + len(backer) - 1, start + len(backer)):
            assert (addr in view) == (addr in loader.memory)


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


def main():
    g = globals()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()


if __name__ == "__main__":
    main()
