#!/usr/bin/env python
from __future__ import annotations

import os

import cle
from cle.backends.elf.relocation.amd64 import R_X86_64_RELATIVE

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

# The fixture is a shared object linked with -Wl,-Ttext-segment=0x400000, so its
# lowest PT_LOAD sits at 0x400000 rather than at zero. Its three
# R_X86_64_RELATIVE relocations fill a pointer table with the addresses of
# alpha, beta and delta.
FIXTURE = os.path.join(TEST_BASE, "x86_64", "relative_reloc_nonzero_base.so")
POINTEES = ("alpha", "beta", "delta")


def check_relative_pointer_table(base_addr):
    """An R_*_RELATIVE relocation writes the load bias plus the addend.

    The bias is ``mapped_base - linked_base``. CLE used to write
    ``mapped_base + addend``, which is the same number only when the object was
    linked at zero -- the case for an ordinary shared library, and not the case
    for a PIE the linker gave a non-zero text segment address. On such an object
    every relative relocation landed ``linked_base`` bytes too high, so pointer
    tables in .data.rel.ro pointed past the end of the image.
    """
    main_opts = {"backend": "elf"}
    if base_addr is not None:
        main_opts["base_addr"] = base_addr
    ld = cle.Loader(FIXTURE, auto_load_libs=False, main_opts=main_opts)
    obj = ld.main_object

    assert obj.linked_base == 0x400000
    relocs = [r for r in obj.relocs if isinstance(r, R_X86_64_RELATIVE)]
    assert len(relocs) == len(POINTEES)

    table = obj.get_symbol("table")
    assert table is not None
    for index, name in enumerate(POINTEES):
        pointee = obj.get_symbol(name)
        assert pointee is not None
        word = ld.memory.unpack_word(table.rebased_addr + index * obj.arch.bytes)
        assert word == pointee.rebased_addr
        assert obj.min_addr <= word <= obj.max_addr
        pointed_at = ld.find_symbol(word)
        assert pointed_at is not None and pointed_at.name == name


def test_relative_relocation_at_the_linked_base():
    # mapped_base == linked_base, so the bias is zero and the addend is the answer.
    check_relative_pointer_table(None)


def test_relative_relocation_rebased():
    # A non-zero bias on top of a non-zero linked base: the two terms the old
    # expression conflated are both non-zero and different.
    check_relative_pointer_table(0x1000000)


def test_relative_relocation_at_a_zero_linked_base():
    """An object linked at zero relocates exactly as it did before.

    A modern toolchain links every shared library and almost every PIE at zero,
    where the bias and the mapped base are the same number. That is why a loader
    can confuse the two and stay correct on nearly everything, and it is the case
    this must leave alone.
    """
    libc = os.path.join(TEST_BASE, "x86_64", "libc.so.6")
    ld = cle.Loader(libc, auto_load_libs=False, main_opts={"backend": "elf", "base_addr": 0x5000000})
    obj = ld.main_object

    assert obj.linked_base == 0
    relocs = [r for r in obj.relocs if isinstance(r, R_X86_64_RELATIVE) and r.resolvedby is None]
    assert relocs
    for reloc in relocs:
        assert reloc.value == obj.mapped_base + reloc.addend
        assert obj.min_addr <= reloc.value <= obj.max_addr


if __name__ == "__main__":
    test_relative_relocation_at_the_linked_base()
    test_relative_relocation_rebased()
    test_relative_relocation_at_a_zero_linked_base()
