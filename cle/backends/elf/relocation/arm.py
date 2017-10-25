import logging
from . import generic
from .elfreloc import ELFReloc

l = logging.getLogger('cle.backends.elf.relocations.arm')
arch = 'ARM'

# Reference: "ELF for the ARM Architecture ABI r2.10"
# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf

def _applyReloc(inst, result, mask=0xFFFFFFFF):
    """
    Applies the specified mask to the relocation and verifies that the mask
    is valid for the given result.
    """
    try:
        assert not (result & ~mask)                 # pylint: disable=superfluous-parens
    except AssertionError as e:
        l.warning("Relocation failed: %r", e)
        return 0                                    # worst case, you hook it yourself
    return ((inst & ~mask) | (result & mask))       # pylint: disable=superfluous-parens

def _isThumbFunc(symbol, addr):
    """
    Checks whether the provided symbol and address is a Thumb function by
    verifying the LSB is 1 and the symbol is STT_FUNC.
    """
    return (addr % 2 == 1) and symbol.is_function

class R_ARM_CALL(ELFReloc):
    """
    Relocate R_ARM_CALL symbols via instruction modification. It additionally
    handles R_ARM_PC24 and R_ARM_JUMP24. The former is deprecated and is now
    just the same as R_ARM_CALL.

    R_ARM_JUMP24 doesn't need the Thumb check. Technically, if the Thumb check
    succeeds on R_ARM_JUMP24, it's a bad call that shouldn't have been generated
    by the linker, so we may as well as just treat it like R_ARM_CALL.

    Class: Static
    Type: ARM (R_ARM_CALL, R_ARM_JUMP24); Deprecated (R_ARM_PC24)
    Code: 1 (R_ARM_PC24), 28 (R_ARM_CALL), 29 (R_ARM_JUMP24)
    Operation: ((S + A) | T) - P
        - S is the address of the symbol
        - A is the addend
        - P is the target location (place being relocated)
        - T is 1 if the symbol is of type STT_FUNC and addresses a Thumb instruction
    """

    @property
    def value(self):
        P = self.rebased_addr                           # Location of this instruction
        A = inst = self.addend                          # The instruction
        S = self.resolvedby.rebased_addr                # The symbol's "value", where it points to
        T = _isThumbFunc(self.symbol, S)

        if inst & 0x00800000: A |= 0xFF000000           # Sign extend to 32-bits
        result = ((S + (A << 2)) | T) - P               # Do the initial work
        imm24 = (result & 0x03FFFFFE) >> 2              # Sign_extend(inst[25:2])

        if T:                                           # Do Thumb relocation
            mask = 0xFF000000
            bit_h = (result & 0x02) >> 1
            result = _applyReloc(inst, (0xFA | bit_h), mask)
        else:                                           # Do ARM relocation
            mask = 0xFFFFFF
            result = _applyReloc(inst, imm24, mask)

        l.debug("%s relocated as R_ARM_CALL with new instruction: %#x", self.symbol.name, result)
        return result

class R_ARM_PREL31(ELFReloc):
    """
    Relocate R_ARM_PREL31 symbols via instruction modification. The difference
    between this and R_ARM_CALL/R_ARM_PC24/R_ARM_JUMP24 is that it's a data
    relocation

    Class: Static
    Type: Data
    Code: 42
    Operation: ((S + A) | T) - P
        - S is the address of the symbol
        - A is the addend
        - P is the target location (place being relocated)
        - T is 1 if the symbol is of type STT_FUNC and addresses a Thumb instruction
    """

    @property
    def value(self):
        P = self.rebased_addr                           # Location of this instruction
        A = self.addend                                 # The instruction
        S = self.resolvedby.rebased_addr                # The symbol's "value", where it points to
        T = _isThumbFunc(self.symbol, S)

        if A & 0x01000000: A |= 0xF1000000              # Sign extend 31-bits
        result = ((S + A) | T) - P                      # Do the initial work
        mask = 0x7FFFFFFF
        rel31 = result & mask
        result = _applyReloc(A, rel31, mask)
        l.debug("%s relocated as R_ARM_PREL31 to: 0x%x", self.symbol.name, result)
        return result

class R_ARM_REL32(ELFReloc):
    """
    Relocate R_ARM_REL32 symbols. This is essentially the same as
    generic.GenericPCRelativeAddendReloc with the addition of a check
    for whether or not the target is Thumb.

    Class: Static
    Type: Data
    Code: 3
    Operation: ((S + A) | T) - P
        - S is the address of the symbol
        - A is the addend
        - P is the target location (place being relocated)
        - T is 1 if the symbol is of type STT_FUNC and addresses a Thumb instruction
    """

    @property
    def value(self):
        P = self.rebased_addr                           # Location of this instruction
        A = self.addend                                 # The instruction
        S = self.resolvedby.rebased_addr                # The symbol's "value", where it points to
        T = _isThumbFunc(self.symbol, S)
        result = ((S + A) | T) - P
        l.debug("%s relocated as R_ARM_REL32 to: 0x%x", self.symbol.name, result)
        return result

class R_ARM_ABS32(ELFReloc):
    """
    Relocate R_ARM_ABS32 symbols. This is essentially the same as
    generic.GenericAbsoluteAddendReloc with the addition of a check
    for whether or not the target is Thumb.

    Class: Static
    Type: Data
    Code: 3
    Operation: (S + A) | T
        - S is the address of the symbol
        - A is the addend
        - T is 1 if the symbol is of type STT_FUNC and addresses a Thumb instruction
    """

    @property
    def value(self):
        A = self.addend                                 # The instruction
        S = self.resolvedby.rebased_addr                # The symbol's "value", where it points to
        T = _isThumbFunc(self.symbol, S)
        result = (S + A) | T
        l.debug("%s relocated as R_ARM_ABS32 to: 0x%x", self.symbol.name, result)
        return result

class R_ARM_COPY(generic.GenericCopyReloc):
    pass

class R_ARM_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_ARM_JUMP_SLOT(generic.GenericJumpslotReloc):
    pass

class R_ARM_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_ARM_ABS32_NOI(generic.GenericAbsoluteAddendReloc):
    pass

class R_ARM_REL32_NOI(generic.GenericPCRelativeAddendReloc):
    pass

class R_ARM_TLS_DTPMOD32(generic.GenericTLSModIdReloc):
    pass

class R_ARM_TLS_DTPOFF32(generic.GenericTLSDoffsetReloc):
    pass

class R_ARM_TLS_TPOFF32(generic.GenericTLSOffsetReloc):
    pass

class R_ARM_JUMP24(R_ARM_CALL):
    pass

class R_ARM_PC24(R_ARM_CALL):
    pass
