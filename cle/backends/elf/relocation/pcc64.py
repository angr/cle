import logging
from . import generic
from .elfreloc import ELFReloc

l = logging.getLogger(name=__name__)

# http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf
arch = 'PPC64'

class R_PPC64_JMP_SLOT(ELFReloc):
    def relocate(self):
        if self.owner.is_ppc64_abiv1:
            # R_PPC64_JMP_SLOT
            # http://osxr.org/glibc/source/sysdeps/powerpc/powerpc64/dl-machine.h?v=glibc-2.15#0405
            # copy an entire function descriptor struct
            addr = self.resolvedby.owner.memory.unpack_word(self.resolvedby.relative_addr)
            toc = self.resolvedby.owner.memory.unpack_word(self.resolvedby.relative_addr + 8)
            aux = self.resolvedby.owner.memory.unpack_word(self.resolvedby.relative_addr + 16)
            self.owner.memory.pack_word(self.relative_addr, addr)
            self.owner.memory.pack_word(self.relative_addr + 8, toc)
            self.owner.memory.pack_word(self.relative_addr + 16, aux)
        else:
            self.owner.memory.pack_word(self.relative_addr, self.resolvedby.rebased_addr)
        return True

class R_PPC64_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_PPC64_IRELATIVE(generic.GenericIRelativeReloc):
    pass

class R_PPC64_ADDR64(generic.GenericAbsoluteAddendReloc):
    pass

class R_PPC64_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_PPC64_DTPMOD64(generic.GenericTLSModIdReloc):
    pass

class R_PPC64_DTPREL64(generic.GenericTLSDoffsetReloc):
    pass

class R_PPC64_TPREL64(generic.GenericTLSOffsetReloc):
    pass

class R_PPC64_REL24(ELFReloc):
    """
    Relocation Type: 10
    Calculation: (S + A - P) >> 2
    Field: low24*
    """
    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        P = self.rebased_addr
        return (S + A - P) >> 2

    def relocate(self):
        if not self.resolved:
            return False
        instr = self.owner.memory.unpack_word(self.relative_addr, size=4) & 0b11111100000000000000000000000011
        imm = self.value & 0xFFFFFF
        self.owner.memory.pack_word(self.relative_addr, instr | (imm << 2), size=4)
        return True

class R_PPC64_TOC16_LO(ELFReloc):
    """
    Relocation Type: 48
    Calculation: #lo(S + A - .TOC.)
    Field: half16
    """
    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        if self.owner.ppc64_initial_rtoc is None:
            l.warning(".TOC. value not found")
            return (S + A) & 0xFFFF
        TOC = self.owner.ppc64_initial_rtoc
        return (S + A - TOC) & 0xFFFF

    def relocate(self):
        if not self.resolved:
            return False
        self.owner.memory.pack_word(self.relative_addr, self.value, size=2)
        return True

class R_PPC64_TOC16_HI(ELFReloc):
    """
    Relocation Type: 49
    Calculation: #hi(S + A - .TOC.)
    Field: half16
    """
    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        if self.owner.ppc64_initial_rtoc is None:
            l.warning(".TOC. value not found")
            return ((S + A) >> 16) & 0xFFFF
        TOC = self.owner.ppc64_initial_rtoc
        return ((S + A - TOC) >> 16) & 0xFFFF

    def relocate(self):
        if not self.resolved:
            return False
        self.owner.memory.pack_word(self.relative_addr, self.value, size=2)
        return True

class R_PPC64_TOC16_HA(ELFReloc):
    """
    Relocation Type: 50
    Calculation: #ha(S + A - .TOC.)
    Field: half16
    """
    @property
    def value(self):
        A = self.addend
        S = self.resolvedby.rebased_addr
        if self.owner.ppc64_initial_rtoc is None:
            l.warning(".TOC. value not found")
            return ((((S + A) >> 16) + (1 if ((S + A) & 0x8000) else 0)) & 0xFFFF)
        TOC = self.owner.ppc64_initial_rtoc
        return ((((S + A - TOC) >> 16) + (1 if ((S + A - TOC) & 0x8000) else 0)) & 0xFFFF)

    def relocate(self):
        if not self.resolved:
            return False
        self.owner.memory.pack_word(self.relative_addr, self.value, size=2)
        return True

class R_PPC64_TOC(ELFReloc):
    """
    Relocation Type: 51
    Calculation: .TOC.
    Field: doubleword64
    """
    @property
    def value(self):
        if self.owner.ppc64_initial_rtoc is None:
            l.warning(".TOC. value not found")
            return 0
        return self.owner.ppc64_initial_rtoc
