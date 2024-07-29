from __future__ import annotations

import os

import cle

test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


def test_progname():
    filename = os.path.join(test_location, "x86_64", "cat")
    ld = cle.Loader(filename, auto_load_libs=False)
    progname_ptr_symbol = ld.find_symbol("__progname")
    progname_ptr = ld.memory.unpack_word(progname_ptr_symbol.rebased_addr)

    assert progname_ptr != 0

    progname = ld.memory.load(progname_ptr, 8)
    assert progname == b"program\0"


def test_got_relocation():
    filename = os.path.join(test_location, "x86_64", "multiarch_main_main.o")
    ld = cle.Loader(filename)

    reloc = ld.main_object.relocs[1]
    assert reloc.symbol.name == "vex_failure_exit"
    assert reloc.symbol.resolvedby.name == "got.vex_failure_exit"

    ptr = ld.memory.unpack_word(reloc.symbol.resolvedby.rebased_addr)
    final_symbol = ld.find_symbol(ptr)

    assert final_symbol is not None
    assert final_symbol.name == "vex_failure_exit"
    assert final_symbol.is_extern


if __name__ == "__main__":
    test_progname()
    test_got_relocation()
