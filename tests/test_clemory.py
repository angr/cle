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


def test_clemory_find_bounds():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory

    # A match that ends on the last byte of the searched range is still a match. The default
    # search_max is max_addr, so this is the last eight bytes of the loaded image.
    end = memory.max_addr
    tail = memory.load(end - 8, 8)
    assert (end - 8) in set(memory.find(tail))

    needle = b"SOSNEAKY"
    (addr,) = memory.find(needle)

    # search_max is exclusive: a range ending where the match ends still reports it.
    assert list(memory.find(needle, search_max=addr + len(needle))) == [addr]
    assert list(memory.find(needle, search_max=addr + len(needle) - 1)) == []

    # search_min bounds where a match may start. A backer is out of range once search_min is
    # past the end of the backer, not past its start plus the length of the needle.
    assert list(memory.find(needle, search_min=addr)) == [addr]
    assert list(memory.find(needle, search_min=addr + 1)) == []


def test_clemory_find_stays_inside_its_backers():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory

    # The empty bytestring is the only needle a buffer reports at the offset one past its own
    # end, and that offset is not an address in memory. fauxware leaves a gap after each of its
    # first two backers, so master reports two addresses here that it does not contain.
    assert [addr for addr in memory.find(b"") if addr not in memory] == []


def test_clemory_find_stays_inside_the_range_it_was_given():
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    memory = loader.memory
    entry = loader.main_object.entry

    # A zero-length match has no bytes to run past search_max, so only a bound on where a match
    # may start keeps the empty bytestring out of the searched range's own end.
    assert list(memory.find(b"", search_min=entry, search_max=entry + 4)) == [
        entry,
        entry + 1,
        entry + 2,
        entry + 3,
    ]


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
