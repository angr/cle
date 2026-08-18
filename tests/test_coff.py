# pylint:disable=no-self-use
from __future__ import annotations

import os
import struct
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def section_vaddr(obj, name: str) -> int:
    return next(section.vaddr for section in obj.sections if section.name == name)


class TestCoff(unittest.TestCase):
    """
    Test COFF loader.
    """

    def test_x86(self):
        exe = os.path.join(TEST_BASE, "tests", "x86", "fauxware.obj")
        ld = cle.Loader(exe, auto_load_libs=True)
        symbol_names = {sym.name for sym in ld.main_object.symbols}
        assert "_main" in symbol_names
        assert "_accepted" in symbol_names
        assert "_rejected" in symbol_names
        assert "_authenticate" in symbol_names

    def test_x86_64(self):
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.obj")
        ld = cle.Loader(exe, auto_load_libs=True)
        symbol_names = {sym.name for sym in ld.main_object.symbols}
        assert "main" in symbol_names
        assert "accepted" in symbol_names
        assert "rejected" in symbol_names
        assert "authenticate" in symbol_names

    def test_long_section_names_come_from_the_string_table(self):
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_long_section_names.obj")
        ld = cle.Loader(exe, auto_load_libs=False)
        assert [section.name for section in ld.main_object.sections] == [
            ".rdata$zzz",
            ".debug$S",
            ".gcc_except_table",
        ]

    def test_dir32_relocation_wraps_at_the_field_width(self):
        # The object stores the addend -6 at the start of .text and defines _target 8 bytes in.
        addend = -6

        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_reloc_dir32.obj")
        ld = cle.Loader(exe, auto_load_libs=False)
        target_symbol = ld.main_object.get_symbol("_target")
        assert target_symbol is not None

        # Adding the symbol's address to the addend's 32-bit pattern carries past the top of the field.
        field_addr = section_vaddr(ld.main_object, ".text")
        assert ld.memory.load(field_addr, 4) == struct.pack("<I", (target_symbol.rebased_addr + addend) % 2**32)

    def test_rel32_relocation_encodes_a_negative_displacement(self):
        # The object holds a backwards call: _callee at offset 0, and a displacement field at
        # offset 5 storing the addend -4. Both live in .text, so the result does not depend on
        # where the object is mapped.
        addend, callee_offset, field_offset = -4, 0, 5
        expected = addend + callee_offset - (field_offset + 4)

        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_reloc_rel32.obj")
        unrelocated = cle.Loader(exe, auto_load_libs=False, perform_relocations=False)
        assert unrelocated.main_object.relocs[0].value == expected

        ld = cle.Loader(exe, auto_load_libs=False)
        field_addr = section_vaddr(ld.main_object, ".text") + field_offset
        assert ld.memory.load(field_addr, 4) == struct.pack("<i", expected)

    def test_uninitialized_section_gets_space_of_its_own(self):
        # .bss states no PointerToRawData because it has no bytes in the file, and this object's
        # is 0x1000 long -- far past the 0xb4 where .text begins. Mapped at the file offset it
        # states, it lies over the file header and the whole of .text.
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_bss.obj")
        ld = cle.Loader(exe, auto_load_libs=False)
        obj = ld.main_object
        bss = next(section for section in obj.sections if section.name == ".bss")
        text = next(section for section in obj.sections if section.name == ".text")

        assert bss.memsize == 0x1000
        assert bss.vaddr >= text.vaddr + text.memsize
        assert obj.find_section_containing(text.vaddr) is text
        # Uninitialized data reads as zero, not as whatever the file happens to hold there.
        assert ld.memory.load(bss.vaddr, bss.memsize) == bytes(bss.memsize)
        buffer_symbol = obj.get_symbol("_buffer")
        assert buffer_symbol is not None
        assert buffer_symbol.rebased_addr == bss.vaddr


if __name__ == "__main__":
    unittest.main()
