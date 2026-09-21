#!/usr/bin/env python
from __future__ import annotations

import logging
import struct
import tempfile
from pathlib import Path

import cle
from cle.backends.macho.macho_enums import LoadCommands as LC

TEST_BASE = Path(__file__).resolve().parent.parent.parent / "binaries"

# `terramate` out of the official Homebrew bottle for tenv 4.15.1, x86_64 macOS. Go's internal linker is
# the toolchain still shipping LC_UNIXTHREAD instead of LC_MAIN, and it stores an x86_THREAD_STATE64
# whose __rip is the entry point. `otool -l` puts the command at file offset 0x650, command 6 of 14.
FIXTURE = TEST_BASE / "tests" / "x86_64" / "terramate.macho"
UNIXTHREAD_OFFSET = 0x650
FLAVOR_FIELD = 8
COUNT_FIELD = 12
ENTRY = 0x1081180
SEGMENTS = ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"]

# x86_FLOAT_STATE64 from mach/i386/thread_status.h. A thread state LC_UNIXTHREAD is allowed to carry,
# but one with no program counter in it, so there is nothing for the loader to take an entry point from.
X86_FLOAT_STATE64 = 5


def load(path: Path | str) -> cle.MachO:
    ld = cle.Loader(str(path), main_opts={"backend": "mach-o"}, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.MachO)
    return ld.main_object


def patch_unixthread(field: int, value: int) -> Path:
    """
    A copy of the fixture with one 32 bit field of its LC_UNIXTHREAD command overwritten.

    :param field:   Offset of the field within the command.
    :param value:   Value to write there.
    """
    data = bytearray(FIXTURE.read_bytes())
    command, _cmdsize = struct.unpack_from("<2I", data, UNIXTHREAD_OFFSET)
    assert command == LC.LC_UNIXTHREAD, "the fixture's thread command moved, update UNIXTHREAD_OFFSET"
    struct.pack_into("<I", data, UNIXTHREAD_OFFSET + field, value)
    handle = tempfile.NamedTemporaryFile(suffix=".macho", delete=False)
    with handle:
        handle.write(data)
    return Path(handle.name)


def test_entry_point_comes_from_the_thread_state():
    # Read as an ARM thread state this comes back with the last of the 16 words the command declares
    # rather than __rip, and dispatching on the flavor alone used to refuse the binary outright.
    obj = load(FIXTURE)
    assert obj.arch.name == "AMD64"
    assert obj.unixthread_pc == ENTRY
    assert obj.entry == ENTRY


def test_flavor_without_a_known_layout_still_loads():
    path = patch_unixthread(FLAVOR_FIELD, X86_FLOAT_STATE64)
    try:
        obj = load(path)
    finally:
        path.unlink()
    # The entry point is all the command contributes, so the rest of the binary still loads without it
    assert obj.unixthread_pc is None
    assert obj.entry == 0
    assert [segment.segname for segment in obj.segments] == SEGMENTS


def test_thread_state_shorter_than_its_flavor_still_loads():
    # Two words is nowhere near an x86_thread_state64_t, so reading one would run past the command
    path = patch_unixthread(COUNT_FIELD, 2)
    try:
        obj = load(path)
    finally:
        path.unlink()
    assert obj.unixthread_pc is None
    assert obj.entry == 0
    assert [segment.segname for segment in obj.segments] == SEGMENTS


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_entry_point_comes_from_the_thread_state()
    test_flavor_without_a_known_layout_still_loads()
    test_thread_state_shorter_than_its_flavor_still_loads()
