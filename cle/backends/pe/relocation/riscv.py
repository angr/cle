from __future__ import annotations

from .pereloc import PEReloc


class IMAGE_REL_BASED_RISCV_HIGH20(PEReloc):
    __slots__ = ()


class IMAGE_REL_BASED_RISCV_LOW12I(PEReloc):
    __slots__ = ()


class IMAGE_REL_BASED_RISCV_LOW12S(PEReloc):
    __slots__ = ()


relocation_table_riscv = {
    5: IMAGE_REL_BASED_RISCV_HIGH20,
    7: IMAGE_REL_BASED_RISCV_LOW12I,
    8: IMAGE_REL_BASED_RISCV_LOW12S,
}

__all__ = ("relocation_table_riscv",)
