from __future__ import annotations

import struct

from cle.address_translator import AT

from .pereloc import PEReloc


class IMAGE_REL_BASED_ARM_MOV32(PEReloc):
    __slots__ = ()


class IMAGE_REL_BASED_THUMB_MOV32(PEReloc):
    """
    The fixup site is a MOVW.W/MOVT.W pair that materialises a 32-bit address in a
    register, one halfword per instruction.
    """

    __slots__ = ()

    @property
    def value(self):
        org_bytes = self.owner.memory.load(self.relative_addr, 8)
        movw, movt = struct.unpack("<II", org_bytes)
        org_value = (_thumb_mov_imm16(movt) << 16) | _thumb_mov_imm16(movw)
        rebased_value = AT.from_lva(org_value, self.owner).to_mva()
        return struct.pack(
            "<II",
            _thumb_mov_set_imm16(movw, rebased_value & 0xFFFF),
            _thumb_mov_set_imm16(movt, (rebased_value >> 16) & 0xFFFF),
        )


def _thumb_mov_imm16(instr):
    """
    Read the imm16 encoded across the two halfwords of a T32 MOVW or MOVT instruction,
    which is held as imm4:i:imm3:imm8.
    """
    first, second = instr & 0xFFFF, instr >> 16
    return ((first & 0xF) << 12) | (((first >> 10) & 1) << 11) | (((second >> 12) & 0x7) << 8) | (second & 0xFF)


def _thumb_mov_set_imm16(instr, imm16):
    first, second = instr & 0xFFFF, instr >> 16
    first = (first & ~0x040F) | (((imm16 >> 11) & 1) << 10) | ((imm16 >> 12) & 0xF)
    second = (second & ~0x70FF) | (((imm16 >> 8) & 0x7) << 12) | (imm16 & 0xFF)
    return (second << 16) | first


relocation_table_arm = {
    5: IMAGE_REL_BASED_ARM_MOV32,
    7: IMAGE_REL_BASED_THUMB_MOV32,
}

__all__ = ("relocation_table_arm",)
