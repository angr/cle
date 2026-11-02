#!/usr/bin/env python
from __future__ import annotations

import os
import struct
import unittest

import cle
from cle.backends.pe.relocation.arm import IMAGE_REL_BASED_THUMB_MOV32
from cle.backends.pe.relocation.generic import IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

ARM64_PE = os.path.join(TEST_BASE, "tests", "aarch64", "windows", "pe_reloc_arm64.exe")
ARMNT_PE = os.path.join(TEST_BASE, "tests", "armel", "windows", "pe_reloc_armnt.exe")

REBASE_DELTA = 0x10000


def load(path, base_addr=None):
    main_opts = {"backend": "pe"}
    if base_addr is not None:
        main_opts["base_addr"] = base_addr
    return cle.Loader(path, auto_load_libs=False, main_opts=main_opts).main_object


def thumb_mov32_immediate(data):
    """
    Read the 32-bit address a T32 MOVW/MOVT pair materialises. Each instruction carries one
    halfword of it, encoded as imm4:i:imm3:imm8 across the instruction's two halfwords.
    """
    halfwords = struct.unpack("<HHHH", data)
    parts = []
    for first, second in (halfwords[:2], halfwords[2:]):
        parts.append(
            ((first & 0xF) << 12) | (((first >> 10) & 1) << 11) | (((second >> 12) & 0x7) << 8) | (second & 0xFF)
        )
    return (parts[1] << 16) | parts[0]


# pylint: disable=no-self-use
class TestPEBaseRelocations(unittest.TestCase):
    """
    Base relocations of PE images built for architectures other than x86 and x86-64.
    """

    def test_aarch64(self):
        obj = load(ARM64_PE)
        assert obj.arch.name == "AARCH64"
        relocs = [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_DIR64)]
        assert sorted(r.relative_addr for r in relocs) == [0x2000, 0x2008, 0x2010]
        assert obj.memory.unpack_word(0x2000, size=8) == 0x1400011B8

    def test_aarch64_rebased(self):
        obj = load(ARM64_PE)
        moved = load(ARM64_PE, obj.linked_base + REBASE_DELTA)
        relocs = [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_DIR64)]
        assert relocs
        for reloc in relocs:
            linked = obj.memory.unpack_word(reloc.relative_addr, size=8)
            rebased = moved.memory.unpack_word(reloc.relative_addr, size=8)
            assert rebased == linked + REBASE_DELTA

    def test_armnt(self):
        obj = load(ARMNT_PE)
        assert obj.arch.name == "ARMEL"
        highlow = [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_HIGHLOW)]
        thumb_mov32 = [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_THUMB_MOV32)]
        assert sorted(r.relative_addr for r in highlow) == [0x2000, 0x2004, 0x2008]
        assert sorted(r.relative_addr for r in thumb_mov32) == [0x104C, 0x1130]
        # the MOVW/MOVT pair at 0x104c materialises the address of the function pointer table
        assert thumb_mov32_immediate(obj.memory.load(0x104C, 8)) == 0x402000

    def test_armnt_rebased(self):
        obj = load(ARMNT_PE)
        moved = load(ARMNT_PE, obj.linked_base + REBASE_DELTA)
        highlow = [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_HIGHLOW)]
        thumb_mov32 = [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_THUMB_MOV32)]
        assert highlow and thumb_mov32
        for reloc in highlow:
            linked = obj.memory.unpack_word(reloc.relative_addr, size=4)
            rebased = moved.memory.unpack_word(reloc.relative_addr, size=4)
            assert rebased == linked + REBASE_DELTA
        for reloc in thumb_mov32:
            linked = thumb_mov32_immediate(obj.memory.load(reloc.relative_addr, 8))
            rebased = thumb_mov32_immediate(moved.memory.load(reloc.relative_addr, 8))
            assert rebased == linked + REBASE_DELTA

    def test_x86_64_unchanged(self):
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "sioctl.sys")
        obj = load(exe)
        assert obj.arch.name == "AMD64"
        assert [r for r in obj.relocs if isinstance(r, IMAGE_REL_BASED_DIR64)]


if __name__ == "__main__":
    unittest.main()
