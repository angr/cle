import logging
from . import generic
from .elfreloc import ELFReloc

l = logging.getLogger(name=__name__)
arch = 'PPC32'

# Reference: System V Application Binary Interface, PowerPC Processor Supplement
# http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf


# PPC constants/masks to be used in relocations
PPC_WORD32 = 0xFFFFFFFF
PPC_WORD30 = 0xFFFFFFFC
PPC_LOW24 = 0x03FFFFFC
PPC_LOW14 = 0x0020FFFC
PPC_HALF16 = 0xFFFF
PPC_BL_INST = 0x48000001

class R_PPC_ADDR32(generic.GenericAbsoluteAddendReloc):
    pass


class R_PPC_ADDR16_LO(ELFReloc):    # pylint: disable=undefined-variable
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
        result = (result & PPC_HALF16)

        print(self.symbol.name, " relocated as R_PPC_ADDR16_LO to: ", hex(result))
        return result


class R_PPC_ADDR16_HA(ELFReloc):    # pylint: disable=undefined-variable
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
        result = (((result >> 16) + (1 if (result & 0x8000) else 0)) & PPC_HALF16)

        print(self.symbol.name, " relocated as R_PPC_ADDR16_HA to: ", hex(result))
        return result


class R_PPC_REL24(ELFReloc):    # pylint: disable=undefined-variable
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
        print(self.symbol.name, " instruction modified as R_PPC_REL24 to: ", hex(result))
        return result


class R_PPC_COPY(generic.GenericCopyReloc):
    pass

class R_PPC_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_PPC_JMP_SLOT(generic.GenericJumpslotReloc):
    def relocate(self, solist, bypass_compatibility=False):
        if 'DT_PPC_GOT' not in self.owner._dynamic and 'DT_LOPROC' not in self.owner._dynamic:
            l.error("This binary is relocated incorrectly. See https://github.com/angr/cle/issues/142 for details.")
        return super(R_PPC_JMP_SLOT, self).relocate(solist, bypass_compatibility=bypass_compatibility)

class R_PPC_RELATIVE(generic.GenericRelativeReloc):
    pass


class R_PPC_DTPMOD32(generic.GenericTLSModIdReloc):
    pass


class R_PPC_DTPREL32(generic.GenericTLSDoffsetReloc):
    pass


class R_PPC_TPREL32(generic.GenericTLSOffsetReloc):
    pass
