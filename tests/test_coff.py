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

    def test_a_section_table_longer_than_the_file_is_rejected(self):
        # The first 512 bytes of x86/fauxware.obj. Its header declares 29 sections, whose table
        # needs 0x49c bytes counted from the start of the file.
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_truncated_section_table.obj")
        with self.assertRaisesRegex(cle.CLEInvalidBinaryError, "section table"):
            cle.Loader(exe, auto_load_libs=False)

    def test_a_symbol_table_past_the_end_of_the_file_is_rejected(self):
        # The first 2048 bytes of x86/fauxware.obj, which is long enough to hold the whole
        # section table and not the 152 symbols at 0x31c1 or the string table after them.
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_truncated_symbol_table.obj")
        with self.assertRaisesRegex(cle.CLEInvalidBinaryError, "symbol table"):
            cle.Loader(exe, auto_load_libs=False)

    def test_a_relocation_table_past_the_end_of_the_file_is_rejected(self):
        # An otherwise well-formed 108-byte object whose .text points its relocation table at
        # 0x4000000, so everything else the parser reads is in range.
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_reloc_table_past_file.obj")
        with self.assertRaisesRegex(cle.CLEInvalidBinaryError, "relocation table"):
            cle.Loader(exe, auto_load_libs=False)

    def test_the_whole_object_still_loads(self):
        # The bounds above are on what the header declares, so an object that declares only what
        # it holds is unaffected.
        exe = os.path.join(TEST_BASE, "tests", "x86", "fauxware.obj")
        ld = cle.Loader(exe, auto_load_libs=False)
        assert len(ld.main_object.sections) == 29
        assert len(ld.main_object.relocs) == 225

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

    def test_a_relocation_past_the_end_of_its_section_is_skipped(self):
        # The object's one relocation sits at offset 0x10 of a .text section holding 0x10 bytes, so
        # its four-byte field falls on the start of .data, which is filled with 0xaa.
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_reloc_outside_section.obj")
        ld = cle.Loader(exe, auto_load_libs=False, perform_relocations=True)
        assert ld.memory.load(section_vaddr(ld.main_object, ".data"), 0x10) == b"\xaa" * 0x10
        assert ld.main_object.relocs == []

    def test_a_relocation_past_the_end_of_the_file_is_skipped(self):
        # The object's one relocation sits at offset 0x4000000 of .text, which the whole file does
        # not reach.
        exe = os.path.join(TEST_BASE, "tests", "x86", "coff_reloc_outside_file.obj")
        with open(exe, "rb") as f:
            raw = f.read()

        ld = cle.Loader(exe, auto_load_libs=False, perform_relocations=True)
        assert ld.main_object.relocs == []
        assert ld.main_object.memory.load(0, len(raw)) == raw

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


if __name__ == "__main__":
    unittest.main()
