from __future__ import annotations

import logging

from .elfreloc import ELFReloc
from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericJumpslotReloc,
    GenericRelativeReloc,
    GenericTLSDoffsetReloc,
    GenericTLSModIdReloc,
    GenericTLSOffsetReloc,
)

log = logging.getLogger(name=__name__)
arch = "PPC32"

# Reference: System V Application Binary Interface, PowerPC Processor Supplement
# http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf


# PPC constants/masks to be used in relocations
PPC_WORD32 = 0xFFFFFFFF
PPC_WORD30 = 0xFFFFFFFC
PPC_LOW24 = 0x03FFFFFC
PPC_LOW14 = 0x0020FFFC
PPC_HALF16 = 0xFFFF
PPC_BL_INST = 0x48000001


class R_PPC_ADDR32(GenericAbsoluteAddendReloc):
    pass


class R_PPC_ADDR24(ELFReloc):
    """
    Relocation Type: 0x2
    Calculation: (S + A) >> 2
    Field: low24*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = (S + A) >> 2
        return result


class R_PPC_ADDR16(ELFReloc):
    """
    Relocation Type: 0x3
    Calculation: S+A
    Field: half16*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = S + A
        return result


class R_PPC_ADDR16_LO(ELFReloc):  # pylint: disable=undefined-variable
    """
    Relocation Type: 0x4
    Calculation: #lo(S + A)
    Field: half16
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = S + A
        result = result & PPC_HALF16
        return result

    def relocate(self):
        if not self.resolved:
            return False
        self.owner.memory.pack_word(self.relative_addr, self.value, size=2)
        return True


class R_PPC_ADDR16_HI(ELFReloc):
    """
    Relocation Type: 0x5
    Calculation: #hi(S + A)
    Field: half16
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = (S + A) >> 16
        result = result & PPC_HALF16
        return result

    def relocate(self):
        if not self.resolved:
            return False
        self.owner.memory.pack_word(self.relative_addr, self.value, size=2)
        return True


class R_PPC_ADDR16_HA(ELFReloc):  # pylint: disable=undefined-variable
    """
    Relocation Type: 0x6
    Calculation: #ha(S + A)
    Field: half16
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = S + A
        result = ((result >> 16) + (1 if (result & 0x8000) else 0)) & PPC_HALF16
        return result

    def relocate(self):
        if not self.resolved:
            return False
        self.owner.memory.pack_word(self.relative_addr, self.value, size=2)
        return True


class R_PPC_ADDR14(ELFReloc):
    """
    Relocation Type: 0x7
    Calculation: (S + A) >> 2
    Field: low14*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = (S + A) >> 2
        return result


class R_PPC_ADDR14_BRTAKEN(ELFReloc):
    """
    Relocation Type: 0x8
    Calculation: (S + A) >> 2
    Field: low14*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = (S + A) >> 2
        return result


class R_PPC_ADDR14_BRNTAKEN(ELFReloc):
    """
    Relocation Type: 0x9
    Calculation: (S + A) >> 2
    Field: low14*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = (S + A) >> 2
        return result


class R_PPC_REL24(ELFReloc):  # pylint: disable=undefined-variable
    """
    Relocation Type: 0xa
    Calculation: (S + A - P) >> 2
    Field: low24*
    R_PPC_REL24 is a special type of relocation.
    The instruction must be modified for this type.
    This relocation type resolves branch-and-link instructions.
    Prior to relocation, all instances of the branch-and-link instruction
    will consist of the following bytecode: 48 00 00 01.
    The problem with this is that all instances will result in calls to
    the current address - thus an infinite loop.
    After calculating the relocation result in R_PPC_REL24,
    you will have an address offset to the call.
    The result must be resolved to the correct instruction encoding.
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr

        result = (S + A - P) >> 2
        result = (result << 2) & PPC_LOW24
        result = (A & ~PPC_LOW24) | result
        result = result | PPC_BL_INST
        return result


class R_PPC_REL14(ELFReloc):
    """
    Relocation Type: 0xb
    Calculation: (S + A - P) >> 2
    Field: low14*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr

        result = (S + A - P) >> 2
        result = (result << 2) & PPC_LOW14
        result = (A & ~PPC_LOW14) | result
        return result


class R_PPC_REL14_BRTAKEN(ELFReloc):
    """
    Relocation Type: 0xc
    Calculation: (S + A - P) >> 2
    Field: low14*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr

        result = (S + A - P) >> 2
        result = (result << 2) & PPC_LOW14
        result = (A & ~PPC_LOW14) | result
        return result


class R_PPC_REL14_BRNTAKEN(ELFReloc):
    """
    Relocation Type: 0xd
    Calculation: (S + A - P) >> 2
    Field: low14*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr

        result = (S + A - P) >> 2
        result = (result << 2) & PPC_LOW14
        result = (A & ~PPC_LOW14) | result
        return result


class R_PPC_COPY(GenericCopyReloc):
    pass


class R_PPC_GLOB_DAT(GenericJumpslotReloc):
    pass


class R_PPC_JMP_SLOT(GenericJumpslotReloc):
    def relocate(self):
        if "DT_PPC_GOT" not in self.owner._dynamic and "DT_LOPROC" not in self.owner._dynamic:
            # old PowerPC ABI - we overwrite this location with a jump (b, 0x12. .. .. .1) to the actual target
            val = (0x12 << 26) | ((self.value - self.rebased_addr) & 0x3FFFFFE)
            self.owner.memory.pack_word(self.dest_addr, val)
        else:
            super().relocate()


class R_PPC_RELATIVE(GenericRelativeReloc):
    pass


class R_PPC_UADDR32(ELFReloc):
    """
    Relocation Type: 0x18
    Calculation: S + A
    Field: word32
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = S + A
        return result


class R_PPC_UADDR16(ELFReloc):
    """
    Relocation Type: 0x19
    Calculation: S + A
    Field: half16*
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = S + A
        return result


class R_PPC_REL32(ELFReloc):  # pylint: disable=undefined-variable
    """
    Relocation Type: 0x1a
    Calculation: S + A - P
    Field: word32
    """

    @property
    def value(self):
        P = self.rebased_addr
        A = self.addend
        S = self.resolvedby.rebased_addr

        result = (S + A - P) & PPC_WORD32
        return result


class R_PPC_SECTOFF(ELFReloc):
    """
    Relocation Type: 0x21
    Calculation: R + A
    Field: half16*
    """

    @property
    def value(self):
        R = self.relative_addr
        A = self.addend

        result = R + A
        return result


class R_PPC_SECTOFF_LO(ELFReloc):
    """
    Relocation Type: 0x22
    Calculation: #lo(R + A)
    Field: half16
    """

    @property
    def value(self):
        R = self.relative_addr
        A = self.addend

        result = R + A
        result = result & PPC_HALF16
        return result


class R_PPC_SECTOFF_HI(ELFReloc):
    """
    Relocation Type: 0x23
    Calculation: #hi(R + A)
    Field: half16
    """

    @property
    def value(self):
        R = self.relative_addr
        A = self.addend

        result = (R + A) >> 16
        result = result & PPC_HALF16
        return result


class R_PPC_SECTOFF_HA(ELFReloc):
    """
    Relocation Type: 0x24
    Calculation: #ha(R + A)
    Field: half16
    """

    @property
    def value(self):
        R = self.relative_addr
        A = self.addend

        result = R + A
        result = ((result >> 16) + (1 if (result & 0x8000) else 0)) & PPC_HALF16
        return result


class R_PPC_ADDR30(ELFReloc):
    """
    Relocation Type: 0x25
    Calculation: (S + A - P) >> 2
    Field: word30
    """

    @property
    def value(self):
        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr

        result = (S + A - P) >> 2
        return result


class R_PPC_DTPMOD32(GenericTLSModIdReloc):
    pass


class R_PPC_DTPREL32(GenericTLSDoffsetReloc):
    pass


class R_PPC_TPREL32(GenericTLSOffsetReloc):
    pass
