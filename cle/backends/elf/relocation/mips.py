"""Relocation types for MIPS 32-bit.

Reference: https://refspecs.linuxfoundation.org/elf/mipsabi.pdf page 4-19

The main document is old and does not contain all the relocation types. I
could not find a more recent document, so I had to rely on the source code of
GNU binutils for all relocations that are not in the main document. See
include/elf/mips.h in the binutils source code.
"""

from __future__ import annotations

from .generic import (
    GenericAbsoluteAddendReloc,
    GenericAbsoluteReloc,
    GenericCopyReloc,
    GenericRelativeReloc,
    GenericTLSDoffsetReloc,
    GenericTLSModIdReloc,
    GenericTLSOffsetReloc,
)

arch = "MIPS32"


class R_MIPS_32(GenericAbsoluteAddendReloc):
    pass


class R_MIPS_REL32(GenericRelativeReloc):
    pass


class R_MIPS_JUMP_SLOT(GenericAbsoluteReloc):
    pass


class R_MIPS_GLOB_DAT(GenericAbsoluteReloc):
    pass


class R_MIPS_TLS_DTPMOD32(GenericTLSModIdReloc):
    pass


class R_MIPS_TLS_TPREL32(GenericTLSOffsetReloc):
    pass


class R_MIPS_TLS_DTPREL32(GenericTLSDoffsetReloc):
    pass


class R_MIPS_HI16(GenericAbsoluteReloc):
    def relocate(self):
        if not self.resolved:
            return False

        self.owner.memory.pack_word(self.dest_addr, self.value >> 16, size=2)
        return True


class R_MIPS_LO16(GenericAbsoluteReloc):
    def relocate(self):
        if not self.resolved:
            return False

        self.owner.memory.pack_word(self.dest_addr, self.value & 0xFFFF, size=2)
        return True


class R_MIPS_64(GenericAbsoluteAddendReloc):
    pass


class R_MIPS_COPY(GenericCopyReloc):
    pass


class R_MIPS_TLS_DTPMOD64(GenericTLSModIdReloc):
    pass


class R_MIPS_TLS_DTPREL64(GenericTLSDoffsetReloc):
    pass


class R_MIPS_TLS_TPREL64(GenericTLSOffsetReloc):
    pass


relocation_table_mips = {
    # 1: R_MIPS_16,
    2: R_MIPS_32,
    3: R_MIPS_REL32,
    # 4: R_MIPS_26,
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
