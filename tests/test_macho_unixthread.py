#!/usr/bin/env python
from __future__ import annotations

import logging
from pathlib import Path

import cle

TEST_BASE = Path(__file__).resolve().parent.parent.parent / "binaries"

# `terramate` out of the official Homebrew bottle for tenv 4.15.1, x86_64 macOS. Go's internal linker
# still emits LC_UNIXTHREAD rather than LC_MAIN, and stores an x86_THREAD_STATE64 whose __rip is the
# entry point. The command is at file offset 0x650 (`otool -l` calls it load command 6, counting from 0).
FIXTURE = TEST_BASE / "tests" / "x86_64" / "terramate.macho"

# The same binary with one 32-bit field of that command rewritten, built by
# binaries/tests_src/macho_unixthread_variants/build.sh. The flavor of the first is x86_FLOAT_STATE64,
# a thread state LC_UNIXTHREAD is allowed to carry but one with no program counter in it; the word
# count of the second is 2, nowhere near an x86_thread_state64_t.
FLOAT_STATE = TEST_BASE / "tests" / "x86_64" / "terramate_float_thread_state.macho"
SHORT_STATE = TEST_BASE / "tests" / "x86_64" / "terramate_short_thread_state.macho"

ENTRY = 0x1081180
SEGMENTS = ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"]


def load(path: Path | str) -> cle.MachO:
    ld = cle.Loader(str(path), main_opts={"backend": "mach-o"}, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.MachO)
    return ld.main_object


def test_entry_point_comes_from_the_thread_state():
    # Read as an ARM thread state this comes back with the last of the 16 words the command declares
    # rather than __rip, and dispatching on the flavor alone used to refuse the binary outright.
    obj = load(FIXTURE)
    assert obj.arch.name == "AMD64"
    assert obj.unixthread_pc == ENTRY
    assert obj.entry == ENTRY


def test_flavor_without_a_known_layout_still_loads():
    obj = load(FLOAT_STATE)
    # The entry point is all the command contributes, so the rest of the binary still loads without it
    assert obj.unixthread_pc is None
    assert obj.entry == 0
    assert [segment.segname for segment in obj.segments] == SEGMENTS


def test_thread_state_shorter_than_its_flavor_still_loads():
    # Two words is nowhere near an x86_thread_state64_t, so reading one would run past the command
    obj = load(SHORT_STATE)
    assert obj.unixthread_pc is None
    assert obj.entry == 0
    assert [segment.segname for segment in obj.segments] == SEGMENTS


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_entry_point_comes_from_the_thread_state()
    test_flavor_without_a_known_layout_still_loads()
    test_thread_state_shorter_than_its_flavor_still_loads()
