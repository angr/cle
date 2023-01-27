import logging

from .elfreloc import ELFReloc
from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericIRelativeReloc,
    GenericJumpslotReloc,
    GenericRelativeReloc,
    GenericTLSDescriptorReloc,
    GenericTLSDoffsetReloc,
    GenericTLSModIdReloc,
    GenericTLSOffsetReloc,
)

log = logging.getLogger(name=__name__)

# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0056b/IHI0056B_aaelf64.pdf
arch = "AARCH64"


class R_AARCH64_ABS64(GenericAbsoluteAddendReloc):
    pass


class R_AARCH64_COPY(GenericCopyReloc):
    pass


class R_AARCH64_GLOB_DAT(GenericJumpslotReloc):
    pass


class R_AARCH64_JUMP_SLOT(GenericJumpslotReloc):
    pass


class R_AARCH64_RELATIVE(GenericRelativeReloc):
    pass


class R_AARCH64_IRELATIVE(GenericIRelativeReloc):
    pass


class R_AARCH64_TLS_DTPREL(GenericTLSDoffsetReloc):
    pass


class R_AARCH64_TLS_DTPMOD(GenericTLSModIdReloc):
    pass


class R_AARCH64_TLS_TPREL(GenericTLSOffsetReloc):
    pass


class R_AARCH64_TLSDESC(GenericTLSDescriptorReloc):
    RESOLVER_ADDR = 0xFFFF_FFFF_FFFF_FE00


class R_AARCH64_CALL26(ELFReloc):
    """
    Relocation Type: 283
    Calculation: (S + A - P)
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False
        if not ((-(2**27)) <= self.value and self.value < (2**27)):
            log.warning("relocation out of range")
        instr = self.owner.memory.unpack_word(self.relative_addr, size=4) & 0b11111100000000000000000000000000
        imm = self.value >> 2 & 0x3FFFFFF
        self.owner.memory.pack_word(self.relative_addr, instr | imm, size=4)
        return True


class R_AARCH64_ADR_PREL_PG_HI21(ELFReloc):
    """
    Relocation Type: 275
    Calculation: Page(S + A) - Page(P)
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr
        return ((S + A) & ~0xFFF) - (P & ~0xFFF)

    def relocate(self):
        if not self.resolved:
            return False
        if not ((-(2**32)) <= self.value and self.value < (2**32)):
            log.warning("relocation out of range")
        instr = self.owner.memory.unpack_word(self.relative_addr, size=4) & 0b10011111000000000000000000011111
        imm = self.value >> 12 & 0x1FFFFF
        immlo = imm & 0b11
        immhi = imm >> 2
        self.owner.memory.pack_word(self.relative_addr, instr | (immhi << 5) | (immlo << 29), size=4)
        return True


class R_AARCH64_ADD_ABS_LO12_NC(ELFReloc):
    """
    Relocation Type: 275
    Calculation: (S + A)
    """

    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        return S + A

    def relocate(self):
        if not self.resolved:
            return False
        instr = self.owner.memory.unpack_word(self.relative_addr, size=4) & 0b11111111110000000000001111111111
        imm = self.value & 0xFFF
        self.owner.memory.pack_word(self.relative_addr, instr | (imm << 10), size=4)
        return True
