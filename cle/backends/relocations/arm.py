from . import generic
from . import generic_elf
import logging
from . import Relocation
from ...address_translator import AT

l = logging.getLogger('cle.relocations.arm')
arch = 'ARM'

# Reference: "ELF for the ARM Architecture ABI r2.10"
# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0044e/IHI0044E_aaelf.pdf


class ARMRelocation:
    """
    Some shared functionality for ARM relocations.
    """
    @staticmethod
    def _applyReloc(inst, result, mask=0xFFFFFFFF):
        assert not (result & ~mask)
        return ((inst & ~mask) | (result & mask))
        
    @staticmethod
    def _isThumbFunc(symbol, addr):
        return (addr % 2 == 1) and symbol.is_function

class R_ARM_CALL(Relocation):
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
        T = ARMRelocation._isThumbFunc(self.symbol, S)
        
        if inst & 0x00800000: A |= 0xFF000000           # Sign extend to 32-bits
        result = ((S + A) | T) - P                      # Do the initial work
        imm24 = (result & 0x03FFFFFC) >> 2              # Sign_extend(inst[25:2])
        
        if T:                                           # Do Thumb relocation
            mask = 0xFF000000
            bit_h = (result & 0x02) >> 1
            result = ARMRelocation._applyReloc(inst, (0xFA | bit_h), mask)
        else:                                           # Do ARM relocation
            mask = 0xFFFFFF
            result = ARMRelocation._applyReloc(inst, imm24, mask)
            
        self.owner_obj.memory.write_addr_at(AT.from_lva(self.addr, self.owner_obj).to_rva(), result)
        l.debug("%s relocated as R_ARM_CALL/R_ARM_JUMP24 with new instruction: 0x%x", self.symbol.name, result)
        return True
     
class R_ARM_PREL31(Relocation):
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
        T = ARMRelocation._isThumbFunc(self.symbol, S)
        
        if A & 0x01000000: A |= 0xF1000000              # Sign extend 31-bits
        result = ((S + A) | T) - P                      # Do the initial work
        mask = 0x7FFFFFFF
        rel31 = result & mask
        result = ARMRelocation._applyReloc(A, rel31, mask)
        l.debug("%s relocated as R_ARM_PREL31 to: 0x%x", self.symbol.name, result)
        return result

class R_ARM_REL32(Relocation):
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
        T = ARMRelocation._isThumbFunc(self.symbol, S)
        result = ((S + A) | T) - P        
        return result

class R_ARM_ABS32(Relocation):
    """
    Relocate R_ARM_REL32 symbols. This is essentially the same as 
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
        T = ARMRelocation._isThumbFunc(self.symbol, S)
        result = (S + A) | T
        return result
        
R_ARM_COPY          = generic.GenericCopyReloc
R_ARM_GLOB_DAT      = generic.GenericJumpslotReloc
R_ARM_JUMP_SLOT     = generic.GenericJumpslotReloc
R_ARM_RELATIVE      = generic.GenericRelativeReloc
R_ARM_ABS32_NOI     = generic.GenericAbsoluteAddendReloc
R_ARM_REL32_NOI     = generic.GenericPCRelativeAddendReloc

R_ARM_TLS_DTPMOD32  = generic_elf.GenericTLSModIdReloc
R_ARM_TLS_DTPOFF32  = generic_elf.GenericTLSDoffsetReloc
R_ARM_TLS_TPOFF32   = generic_elf.GenericTLSOffsetReloc

R_ARM_JUMP24        = R_ARM_CALL
R_ARM_PC24          = R_ARM_CALL
