"""Relocation types for MIPS 32-bit.

Reference: https://refspecs.linuxfoundation.org/elf/mipsabi.pdf page 4-19

The main document is old and does not contain all the relocation types. I
could not find a more recent document, so I had to rely on the source code of
GNU binutils for all relocations that are not in the main document. See
include/elf/mips.h in the binutils source code.
"""

from __future__ import annotations

import logging
from ctypes import c_int16

from archinfo import Endness

from .elfreloc import ELFReloc
from .generic import (
    GenericAbsoluteAddendReloc,
    GenericAbsoluteReloc,
    GenericCopyReloc,
    GenericRelativeReloc,
    GenericTLSDoffsetReloc,
    GenericTLSModIdReloc,
    GenericTLSOffsetReloc,
)

log = logging.getLogger(name=__name__)

# pylint: disable=missing-class-docstring


class R_MIPS_32(GenericAbsoluteAddendReloc):
    __slots__ = ()


class R_MIPS_REL32(GenericRelativeReloc):
    __slots__ = ()


class R_MIPS_26(GenericAbsoluteReloc):
    __slots__ = ()

    def relocate(self):
        if not self.resolved:
            return False

        original_value = self.owner.memory.unpack_word(self.dest_addr)
        original_value += self.value // 4

        self.owner.memory.pack_word(self.dest_addr, original_value)
        return True


class R_MIPS_JUMP_SLOT(GenericAbsoluteReloc):
    __slots__ = ()


class R_MIPS_GLOB_DAT(GenericAbsoluteReloc):
    __slots__ = ()


class R_MIPS_TLS_DTPMOD32(GenericTLSModIdReloc):
    __slots__ = ()


class R_MIPS_TLS_TPREL32(GenericTLSOffsetReloc):
    __slots__ = ()


class R_MIPS_TLS_DTPREL32(GenericTLSDoffsetReloc):
    __slots__ = ()


class MipsHalfwordReloc(ELFReloc):
    """
    Common behavior of R_MIPS_HI16 and R_MIPS_LO16, which relocate the 16-bit immediate field of
    one instruction each so that the pair computes S + AHL at run time.
    """

    __slots__ = ()

    @property
    def value(self):
        assert self.resolvedby is not None
        # In a REL object the addend lives in the instruction, and what ELFReloc reads at the
        # relocated address is the whole instruction rather than an addend, so only a RELA
        # relocation has a usable one here.
        return self.resolvedby.rebased_addr + (self.addend if self.is_rela else 0)

    @property
    def immediate_addr(self):
        """
        The address of the 16-bit immediate field, which is the low halfword of the instruction.
        """
        if self.arch.memory_endness == Endness.BE:
            return self.dest_addr + 2
        return self.dest_addr

    @property
    def implicit_addend(self):
        """
        The part of the addend the producer left in the immediate field. A RELA relocation
        carries its whole addend in r_addend and overwrites the field instead.
        """
        if self.is_rela:
            return 0
        return self.owner.memory.unpack_word(self.immediate_addr, size=2)


class R_MIPS_HI16(MipsHalfwordReloc):
    __slots__ = ()

    def find_matching_lo16_relocation(self):
        """
        The R_MIPS_LO16 holding the low half of a REL addend, or None if the object has none.
        The ABI requires it to follow its R_MIPS_HI16 in the same relocation table.
        """
        current_hi16_index = self.owner.relocs.index(self)
        return next(
            (
                reloc
                for reloc in self.owner.relocs[current_hi16_index:]
                if (self.symbol == reloc.symbol and type(reloc) is R_MIPS_LO16)
            ),
            None,
        )

    def relocate(self):
        if not self.resolved:
            return False

        value = self.value
        if not self.is_rela:
            # REL splits the addend across the pair, as AHL = (AHI << 16) + (short)ALO, so the
            # low half has to be read out of the matching R_MIPS_LO16 instruction.
            matching_lo16_reloc = self.find_matching_lo16_relocation()
            if matching_lo16_reloc is None:
                log.warning("no R_MIPS_LO16 relocation matching the R_MIPS_HI16 at %#x", self.rebased_addr)
                return False
            value += c_int16(matching_lo16_reloc.implicit_addend).value

        # %high(S + AHL): the halfword that lui loads so that adding the signed low halfword
        # written by the matching R_MIPS_LO16 produces S + AHL again.
        target_value = ((value - c_int16(value).value) >> 16) + self.implicit_addend

        self.owner.memory.pack_word(self.immediate_addr, target_value & 0xFFFF, size=2)
        return True


class R_MIPS_LO16(MipsHalfwordReloc):
    __slots__ = ()

    def relocate(self):
        if not self.resolved:
            return False

        target_value = (self.value + self.implicit_addend) & 0xFFFF

        self.owner.memory.pack_word(self.immediate_addr, target_value, size=2)
        return True


class R_MIPS_64(GenericAbsoluteAddendReloc):
    __slots__ = ()


class R_MIPS_COPY(GenericCopyReloc):
    __slots__ = ()


class R_MIPS_TLS_DTPMOD64(GenericTLSModIdReloc):
    __slots__ = ()


class R_MIPS_TLS_DTPREL64(GenericTLSDoffsetReloc):
    __slots__ = ()


class R_MIPS_TLS_TPREL64(GenericTLSOffsetReloc):
    __slots__ = ()


relocation_table_mips = {
    # 1: R_MIPS_16,
    2: R_MIPS_32,
    3: R_MIPS_REL32,
    4: R_MIPS_26,
    5: R_MIPS_HI16,
    6: R_MIPS_LO16,
    # 7: R_MIPS_GPREL16,
    # 8: R_MIPS_LITERAL,
    # 9: R_MIPS_GOT16,
    # 10: R_MIPS_PC16,
    # 11: R_MIPS_CALL16,
    # 12: R_MIPS_GPREL32,
    # 13: R_MIPS_UNUSED1,
    # 14: R_MIPS_UNUSED2,
    # 15: R_MIPS_UNUSED3,
    # 16: R_MIPS_SHIFT5,
    # 17: R_MIPS_SHIFT6,
    18: R_MIPS_64,
    # 19: R_MIPS_GOT_DISP,
    # 20: R_MIPS_GOT_PAGE,
    # 21: R_MIPS_GOT_OFST,
    # 22: R_MIPS_GOT_HI16,
    # 23: R_MIPS_GOT_LO16,
    # 24: R_MIPS_SUB,
    # 25: R_MIPS_INSERT_A,
    # 26: R_MIPS_INSERT_B,
    # 27: R_MIPS_DELETE,
    # 28: R_MIPS_HIGHER,
    # 29: R_MIPS_HIGHEST,
    # 30: R_MIPS_CALL_HI16,
    # 31: R_MIPS_CALL_LO16,
    # 32: R_MIPS_SCN_DISP,
    # 33: R_MIPS_REL16,
    # 34: R_MIPS_ADD_IMMEDIATE,
    # 35: R_MIPS_PJUMP,
    # 36: R_MIPS_RELGOT,
    # 37: R_MIPS_JALR,
    38: R_MIPS_TLS_DTPMOD32,
    39: R_MIPS_TLS_DTPREL32,
    40: R_MIPS_TLS_DTPMOD64,
    41: R_MIPS_TLS_DTPREL64,
    # 42: R_MIPS_TLS_GD,
    # 43: R_MIPS_TLS_LDM,
    # 44: R_MIPS_TLS_DTPREL_HI16,
    # 45: R_MIPS_TLS_DTPREL_LO16,
    # 46: R_MIPS_TLS_GOTTPREL,
    47: R_MIPS_TLS_TPREL32,
    48: R_MIPS_TLS_TPREL64,
    # 49: R_MIPS_TLS_TPREL_HI16,
    # 50: R_MIPS_TLS_TPREL_LO16,
    51: R_MIPS_GLOB_DAT,
    # 60: R_MIPS_PC21_S2,
    # 61: R_MIPS_PC26_S2,
    # 62: R_MIPS_PC18_S3,
    # 63: R_MIPS_PC19_S2,
    # 64: R_MIPS_PCHI16,
    # 65: R_MIPS_PCLO16,
    126: R_MIPS_COPY,
    127: R_MIPS_JUMP_SLOT,
    # 248: R_MIPS_PC32,
    # 249: R_MIPS_EH,
    # 250: R_MIPS_GNU_REL16_S2,
    # 253: R_MIPS_GNU_VTINHERIT,
    # 254: R_MIPS_GNU_VTENTRY,
}

__all__ = ("relocation_table_mips",)
