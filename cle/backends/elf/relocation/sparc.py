from __future__ import annotations

from .elfreloc import ELFReloc

arch = "sparc:BE:32:default"

# Check The SPARC Architecture Manual for field definitions.


class R_SPARC_HI22(ELFReloc):
    """
    Value: 9
    Field: T-imm22
    Calculation: (S + A) >> 10
    """

    @property
    def value(self):
        result = (self.resolvedby.rebased_addr + self.addend) >> 10
        instr_bytes = self.owner.memory.load(self.relative_addr, 4)
        instr = int.from_bytes(instr_bytes, byteorder="big")
        return instr & 0xFFC00000 | result & 0x3FFFFF


class R_SPARC_WDISP30(ELFReloc):
    """
    Value: 7
    Field: V-disp30
    Calculation: (S + A - P) >> 2
    """

    @property
    def value(self):
        result = (self.resolvedby.rebased_addr + self.addend - self.rebased_addr) >> 2
        instr_bytes = self.owner.memory.load(self.relative_addr, 4)
        instr = int.from_bytes(instr_bytes, byteorder="big")
        return instr & 0xC0000000 | result & 0x3FFFFFFF


class R_SPARC_LO10(ELFReloc):
    """
    Value: 12
    Field: T-simm13
    Calculation: (S + A) & 0x3ff
    """

    @property
    def value(self):
        result = (self.resolvedby.rebased_addr + self.addend) & 0x3FF
        instr_bytes = self.owner.memory.load(self.relative_addr, 4)
        instr = int.from_bytes(instr_bytes, byteorder="big")
        return instr & 0xFFFFE000 | result & 0x1FFF
