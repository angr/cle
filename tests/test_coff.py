# pylint:disable=no-self-use
from __future__ import annotations

import os
import struct
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def addr_of(symbol: cle.Symbol | None) -> int:
    """
    Return the rebased address of a symbol lookup, failing the test if the lookup found nothing.
    """
    assert symbol is not None
    return symbol.rebased_addr


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

    def test_x86_64_pdata_addends(self):
        # A .pdata RUNTIME_FUNCTION holds its function's bounds as two ADDR32NB relocations against the same section
        # symbol, told apart only by their in-place addends. Dropping those left every record an empty range.
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.obj")
        ld = cle.Loader(exe, auto_load_libs=True)

        pdata = next(section for section in ld.main_object.sections if section.name.startswith(".pdata"))
        assert pdata.filesize > 0 and pdata.filesize % 12 == 0
        for record in range(pdata.filesize // 12):
            address = pdata.vaddr + record * 12
            begin, end, _unwind = struct.unpack("<3I", ld.memory.load(address, 12))
            assert begin < end

    def test_unsupported_machine(self):
        exe = os.path.join(TEST_BASE, "tests", "mips", "coff_r4000.obj")

        # Autodetection does not pick the COFF backend for it at all.
        with self.assertRaises(cle.CLECompatibilityError):
            cle.Loader(exe, auto_load_libs=False)

        # Asking for the backend by name reports the machine type that was rejected.
        with self.assertRaises(cle.CLECompatibilityError) as cm:
            cle.Loader(exe, auto_load_libs=False, main_opts={"backend": "COFF"})
        assert "0x0166" in str(cm.exception)

    def test_arm64(self):
        exe = os.path.join(TEST_BASE, "tests", "aarch64", "coff_reloc_arm64.obj")
        ld = cle.Loader(exe, auto_load_libs=False)
        assert type(ld.main_object).__name__ == "Coff"
        assert ld.main_object.arch.name == "AARCH64"

        target = addr_of(ld.main_object.get_symbol("target"))
        aligned = addr_of(ld.main_object.get_symbol("aligned"))
        ext_fn = addr_of(ld.find_symbol("ext_fn"))
        text = section_vaddr(ld.main_object, ".text")
        assert aligned % 16 == 0
        branch, adrp, add, ldr, add_addend, ldr_vector = struct.unpack("<6I", ld.memory.load(text, 24))

        # imm26 is in units of four bytes, relative to the branch itself.
        assert text + _sign_extend(branch, 26) * 4 == ext_fn
        # ADRP forms the target's 4KiB page base; the instructions after it the offset within that page.
        page = (text + 4 + (_sign_extend(((adrp >> 29) & 0x3) | ((adrp >> 3) & 0x1FFFFC), 21) << 12)) & ~0xFFF
        assert page + ((add >> 10) & 0xFFF) == target
        # A load scales its immediate by the access size: four bytes here, sixteen for a vector register.
        assert page + ((ldr >> 10) & 0xFFF) * 4 == target
        assert page + ((ldr_vector >> 10) & 0xFFF) * 16 == aligned
        assert page + ((add_addend >> 10) & 0xFFF) == target + 4
        assert struct.unpack("<Q", ld.memory.load(text + 0x20, 8))[0] == target + 8
        assert struct.unpack("<I", ld.memory.load(text + 0x28, 4))[0] == target - ld.main_object.mapped_base + 4

    def test_armnt(self):
        exe = os.path.join(TEST_BASE, "tests", "armel", "coff_reloc_armnt.obj")
        ld = cle.Loader(exe, auto_load_libs=False)
        assert type(ld.main_object).__name__ == "Coff"
        assert ld.main_object.arch.name == "ARMEL"

        # ARMNT code is Thumb-2 only, so function symbols carry the Thumb bit.
        thumbfn = addr_of(ld.main_object.get_symbol("thumbfn"))
        text = section_vaddr(ld.main_object, ".text")
        assert thumbfn == text + 1

        halfwords = struct.unpack("<10H", ld.memory.load(text, 20))
        movw_hw0, movw_hw1, movt_hw0, movt_hw1, bl_hw0, bl_hw1 = halfwords[:6]
        assert _read_mov_imm16(movw_hw0, movw_hw1) | (_read_mov_imm16(movt_hw0, movt_hw1) << 16) == thumbfn
        assert _read_mov_imm16(*halfwords[6:8]) | (_read_mov_imm16(*halfwords[8:10]) << 16) == thumbfn + 4

        sign = (bl_hw0 >> 10) & 1
        displacement = _sign_extend(
            (sign << 24)
            | ((((bl_hw1 >> 13) & 1) ^ sign ^ 1) << 23)
            | ((((bl_hw1 >> 11) & 1) ^ sign ^ 1) << 22)
            | ((bl_hw0 & 0x3FF) << 12)
            | ((bl_hw1 & 0x7FF) << 1),
            25,
        )
        # The Thumb program counter reads four bytes ahead, and the branch drops its target's Thumb bit.
        assert text + 8 + 4 + displacement == addr_of(ld.find_symbol("ext_fn")) - 1

        # A function whose address is only taken is Thumb code too.
        ext_ptr = addr_of(ld.find_symbol("ext_ptr"))
        assert ext_ptr % 2 == 1
        assert struct.unpack("<I", ld.memory.load(text + 0x18, 4))[0] == ext_ptr


def _sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def _read_mov_imm16(hw0: int, hw1: int) -> int:
    return ((hw0 & 0xF) << 12) | ((hw0 & 0x400) << 1) | ((hw1 & 0x7000) >> 4) | (hw1 & 0xFF)


if __name__ == "__main__":
    unittest.main()
