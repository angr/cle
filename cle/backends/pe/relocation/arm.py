from __future__ import annotations

from .pereloc import PEReloc


class IMAGE_REL_BASED_ARM_MOV32(PEReloc):
    __slots__ = ()


class IMAGE_REL_BASED_THUMB_MOV32(PEReloc):
    __slots__ = ()


relocation_table_arm = {
    5: IMAGE_REL_BASED_ARM_MOV32,
    7: IMAGE_REL_BASED_THUMB_MOV32,
}

__all__ = ("relocation_table_arm",)
