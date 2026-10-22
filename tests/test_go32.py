"""
Tests for the DJGPP go32 backend.

tests_src/dos/build_djgpp.sh builds both inputs from djgpp_hello.c with DJGPP's gcc 12.2.0.
djgpp_hello.exe keeps its COFF symbol table; djgpp_hello_stripped.exe is the same executable without
one. In both, the go32 stub is the file's first 0x800 bytes and the COFF image follows it.
"""

from __future__ import annotations

import os

import cle
from cle.backends.go32 import Go32
from cle.backends.mz import MZ

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
HELLO = os.path.join(TEST_BASE, "tests", "i386", "dos", "djgpp_hello.exe")
HELLO_STRIPPED = os.path.join(TEST_BASE, "tests", "i386", "dos", "djgpp_hello_stripped.exe")

# what the linker wrote into the a.out header and the section table, read back out of the file
ENTRY = 0x19F0
SECTIONS = [(".text", 0x19E8, 0x10A18), (".data", 0x12400, 0x3200), (".bss", 0x15600, 0x4600)]
# from the symbol table of djgpp_hello.exe
MAIN, INCREMENT, COUNTER, BUFFER = 0x1F1D, 0x1F10, 0x124E0, 0x15610
# the address of the rel32 call to _increment in _main
CALL_INCREMENT = 0x1F34


def load(path: str) -> Go32:
    obj = cle.Loader(path, auto_load_libs=False).main_object
    assert isinstance(obj, Go32)
    return obj


def test_loads_the_coff_image():
    for path in (HELLO, HELLO_STRIPPED):
        obj = load(path)
        assert obj.arch.name == "X86"
        assert obj.entry == ENTRY
        assert [(s.name, s.vaddr, s.memsize) for s in obj.sections] == SECTIONS
        text, data, bss = obj.sections
        assert text.is_executable and not text.is_writable
        assert not data.is_executable and data.is_writable
        assert bss.only_contains_uninitialized_data and bss.filesize == 0


def test_mz_declines_the_stub():
    for path in (HELLO, HELLO_STRIPPED):
        with open(path, "rb") as f:
            assert not MZ.is_compatible(f)


def test_symbols_name_their_contents():
    obj = load(HELLO)
    main, increment, counter, buffer = (obj.get_symbol(n) for n in ("_main", "_increment", "_counter", "_buffer"))
    assert main is not None and increment is not None and counter is not None and buffer is not None
    assert [s.relative_addr for s in (main, increment, counter, buffer)] == [MAIN, INCREMENT, COUNTER, BUFFER]
    assert main.is_function and increment.is_function and not counter.is_function
    assert obj.memory.load(CALL_INCREMENT, 1)[0] == 0xE8
    assert CALL_INCREMENT + 5 + obj.memory.unpack_word(CALL_INCREMENT + 1, size=4, signed=True) == INCREMENT
    assert obj.memory.unpack_word(COUNTER, size=4) == 0x1234ABCD
    assert obj.memory.load(BUFFER, 16) == bytes(16)


def test_stripped_image_matches():
    obj, stripped = load(HELLO), load(HELLO_STRIPPED)
    assert not list(stripped.symbols)
    for _, vaddr, size in SECTIONS:
        assert stripped.memory.load(vaddr, size) == obj.memory.load(vaddr, size)
