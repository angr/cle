from __future__ import annotations

from pathlib import Path

import pytest

import cle

TEST_BASE = Path(__file__).resolve().parents[2] / "binaries" / "tests"

# A CGC binary with four loaded segments, linked at 0x60006c4 and with its first executable segment at 0x8048000. The
# base and that segment sitting at different addresses is what makes the object-relative addressing visible.
BINARY = TEST_BASE / "i386" / "patchrex" / "memory_scanner"
EXEC_SEG_ADDR = 0x8048000
DROPPED_SEG_ADDRS = (0x60006C4, 0x804F348, 0x8063000)

# The instruction pointer the dump was taken at. The file's own entry point is 0x6000703, so a loaded object only
# reports this one if the register backer reached it.
DUMP_EIP = 0x8048100
FILE_ENTRY = 0x6000703

# A region a CGC process dump carries that the file itself does not map.
STACK_ADDR = 0xBAAAB000
STACK_DATA = b"\x11" * 0x1000


def load(**main_opts) -> cle.Loader:
    return cle.Loader(BINARY, auto_load_libs=False, main_opts={"backend": "backedcgc", **main_opts})


def test_backed_cgc_keeps_the_code_and_maps_the_dump():
    loader = load(
        memory_backer={STACK_ADDR: STACK_DATA},
        register_backer={"eip": DUMP_EIP, "esp": STACK_ADDR},
    )
    obj = loader.main_object
    assert isinstance(obj, cle.BackedCGC)

    # The executable segment loaded from the file survives; it is the one backer the dump does not replace.
    assert loader.memory.load(EXEC_SEG_ADDR, 4) == b"\x7fCGC"

    # Every other segment the file mapped is dropped, since the dump is the authority on non-code memory. Dropping
    # them has to survive the backer list shrinking as it goes.
    for addr in DROPPED_SEG_ADDRS:
        with pytest.raises(KeyError):
            loader.memory.load(addr, 4)

    # The dump lands where the dump says it lives, not at that address offset by the object's base.
    assert loader.memory.load(STACK_ADDR, 4) == STACK_DATA[:4]

    assert obj.entry == DUMP_EIP
    assert obj.thread_registers() == {"eip": DUMP_EIP, "esp": STACK_ADDR}


def test_backed_cgc_loads_without_either_backer():
    # Both backers are optional, so the backend has to load with neither of them and fall back to the file.
    loader = load()
    obj = loader.main_object

    assert loader.memory.load(EXEC_SEG_ADDR, 4) == b"\x7fCGC"
    assert obj.entry == FILE_ENTRY
    assert obj.thread_registers() == {}
