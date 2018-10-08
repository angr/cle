import logging
from . import generic
from .elfreloc import ELFReloc
from ....errors import CLEOperationError


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
        if result & ~mask:
            raise ValueError('result & ~mask is not 0.')
    except ValueError as ex:
        l.warning("Relocation failed: %r", ex)
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

    - Class: Static
    - Type: ARM (R_ARM_CALL, R_ARM_JUMP24); Deprecated (R_ARM_PC24)
    - Code: 1 (R_ARM_PC24), 28 (R_ARM_CALL), 29 (R_ARM_JUMP24)
    - Operation: ((S + A) | T) - P
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

    - Class: Static
    - Type: Data
    - Code: 42
    - Operation: ((S + A) | T) - P
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

    - Class: Static
    - Type: Data
    - Code: 3
    - Operation: ((S + A) | T) - P
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

    - Class: Static
    - Type: Data
    - Code: 3
    - Operation: (S + A) | T
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

class R_ARM_MOVW_ABS_NC(ELFReloc):
    """
    Relocate R_ARM_MOVW_ABS_NC symbols.

    - Class: Static
    - Type: Instruction
    - Code: 43
    - Operation: (S + A) | T
      - S is the address of the symbol
      - A is the addend
      - T is 1 if the symbol is of type STT_FUNC and addresses a Thumb instruction
    """

    @property
    def value(self):
        inst = self.addend  # The instruction
        S = self.resolvedby.rebased_addr  # The symbol's "value", where it points to
        T = _isThumbFunc(self.symbol, S)
        # initial addend is formed by interpreting the 16-bit literal field
        # of the instruction as a signed value
        A = ((inst & 0xf0000) >> 4) | (inst & 0xfff)
        if (A & 0x8000):
            # two's complement
            A = -((A ^ 0xffff) + 1)
        X = ((S + A) | T)
        MaskX = X & 0xffff
        # inst modification:
        part1 = MaskX >> 12
        part2 = MaskX & 0xFFF
        inst &= 0xfff0f000  # clears inst[11, 0] and inst[19, 16]
        inst |= ((part1 << 16) & 0xf0000)  # inst[19, 16] = part1
        inst |= (part2 & 0xfff)  # inst[11, 0] = part2
        l.debug("%s relocated as R_ARM_MOVW_ABS_NC to: 0x%x", self.symbol.name, inst)
        return inst

class R_ARM_MOVT_ABS(ELFReloc):
    """
    Relocate R_ARM_MOVT_ABS symbols.

    - Class: Static
    - Type: Instruction
    - Code: 44
    - Operation: S + A
      - S is the address of the symbol
      - A is the addend
    """

    @property
    def value(self):
        inst = self.addend  # The instruction
        S = self.resolvedby.rebased_addr  # The symbol's "value", where it points to
        # initial addend is formed by interpreting the 16-bit literal field
        # of the instruction as a signed value
        A = ((inst & 0xf0000) >> 4) | (inst & 0xfff)
        if (A & 0x8000):
            # two's complement
            A = -((A ^ 0xffff) + 1)
        X = (S + A)
        MaskX = X & 0xffff0000
        # inst modification:
        part1 = (MaskX >> 16) >> 12
        part2 = (MaskX >> 16) & 0xFFF
        inst &= 0xfff0f000  # clears inst[11, 0] and inst[19, 16]
        inst |= ((part1 << 16) & 0xf0000)  # inst[19, 16] = part1
        inst |= (part2 & 0xfff)  # inst[11, 0] = part2
        l.debug("%s relocated as R_ARM_MOVT_ABS to: 0x%x", self.symbol.name, inst)
        return inst

class R_ARM_THM_CALL(ELFReloc):
    """
    Relocate R_ARM_THM_CALL symbols via instruction modification.

    - Class: Static
    - Type: ARM (R_ARM_THM_CALL)
    - Code: 10
    - Operation: ((S + A) | T) - P
      - S is the address of the symbol
      - A is the addend
      - P is the target location (place being relocated)
      - T is 1 if the symbol is of type STT_FUNC and addresses a Thumb instruction (This bit is entirely irrelevant because the 1-bit of the address gets shifted off in the encoding)
    - Encoding: See http://hermes.wings.cs.wisc.edu/files/Thumb-2SupplementReferenceManual.pdf
      - Page 71 (3-31) has the chart
      - It appears that it mistakenly references the I1 and I2 bits as J1 and J2 in the chart (see the notes at the bottom of the page -- the ranges don't make sense)
      - However, the J1/J2 bits are XORed with !S bit in this case (see vex implementation: https://github.com/angr/vex/blob/6d1252c7ce8fe8376318b8f8bb8034058454c841/priv/guest_arm_toIR.c#L19219 )
      - Implementation appears correct with the bits placed into offset[23:22]
    """
    def __init__(self, *args, **kwargs):
        super(R_ARM_THM_CALL, self).__init__(*args, **kwargs)
        self._insn_bytes = None

    def resolve_symbol(self, solist, bypass_compatibility=False, thumb=False):
        return super(R_ARM_THM_CALL, self).resolve_symbol(solist,
                                                          bypass_compatibility=bypass_compatibility,
                                                          thumb=True)

    @property
    def value(self):
        P = self.rebased_addr                           # Location of this instruction
        S = self.resolvedby.rebased_addr                # The symbol's "value", where it points to
        T = _isThumbFunc(self.symbol, S)
        A = 0

        # Deconstruct the instruction:
        #  Because this 4-byte instruction is treated as two 2-byte instructions,
        #  the bytes are in the order `b3 b4 b1 b2`, where b4 is the most significant.

        if self._insn_bytes is None:
            self._insn_bytes = self.owner.memory.load(self.relative_addr, 4)

        hi   = (self._insn_bytes[1] << 8) | self._insn_bytes[0]
        lo   = (self._insn_bytes[3] << 8) | self._insn_bytes[2]
        inst = (hi << 16) | lo

        def gen_mask(n_bits, first_bit):
            """
            Builds a mask that captures n_bits, where the first bit captured is first_bit
            """
            return ((1 << n_bits) - 1) << first_bit

        if self.is_rela:
            A = self.addend
        else:
            # Build A (the initial addend)

            A |=  (inst & gen_mask(11,  0)) <<  1                     # A[11:1]  = inst[10:0] (inclusive)
            A |= ((inst & gen_mask(10, 16)) >> 16) << 12              # A[21:12] = inst[25:16]

            sign_bit = bool(inst & gen_mask(1, 26)) & 1               # sign_bit = inst[26]

            J1 = (bool(inst & gen_mask(1, 13)) & 1) ^ (not sign_bit)  # J1 = inst[13] ^ !sign
            J2 = (bool(inst & gen_mask(1, 11)) & 1) ^ (not sign_bit)  # J2 = inst[11] ^ !sign

            A |= J1 << 23                                             # A[23] = J1
            A |= J2 << 22                                             # A[22] = J2

            A &= 0x7fffff

            if sign_bit:
                A |= 0xff800000

        # Compute X, the new offset, from the symbol addr, S, the addend, A,
        #  the thumb flag, T, and PC, P.

        x = (((S + A) | T) - P) & 0xffffffff                          # Also mask to 32 bits

        # Ensure jump is in range

        if x & 0xff800000 != 0 and x & 0xff800000 != 0xff800000:
            raise CLEOperationError("Jump target out of range for reloc R_ARM_THM_CALL (+- 2^23). "
                                    "This may be due to SimProcedures being allocated outside the jump range. "
                                    "If you believe this is the case, set 'rebase_granularity'=0x1000 in the "
                                    "load options.")

        # Rebuild the instruction, first clearing out any previously set offset bits

        #                 offset     1 2  offset
        #          11110S [21:12]  11J?J  [11:1]     (if ? is 1, BL; if ? is 0, BLX)
        inst &= ~0b00000111111111110010111111111111
        #         |       |       |       |       |
        #        32      24      16       8       0

        sign_bit =  bool(x & gen_mask(1, 24)) & 1
        J1       = (bool(x & gen_mask(1, 23)) & 1) ^ (not sign_bit)
        J2       = (bool(x & gen_mask(1, 22)) & 1) ^ (not sign_bit)

        inst |= sign_bit << 26
        inst |= J1       << 13
        inst |= J2       << 11

        inst |=  (x & gen_mask(11,  1)) >> 1
        inst |= ((x & gen_mask(10, 12)) >> 12) << 16

        # Put it back into <little endian short> <little endian short> format

        raw = ((inst & 0x00ff0000) >> 16, (inst & 0xff000000) >> 24,
               (inst & 0x00ff), (inst & 0xff00) >> 8)

        # The relocation handler expects a little-endian result, so flip it around.

        result = (raw[3] << 24) | (raw[2] << 16) | (raw[1] << 8) | raw[0]

        l.debug("%s relocated as R_ARM_THM_CALL with new instruction: %#x", self.symbol.name, result)
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

# EDG says: Implementing these the easy way.
# Inaccuracies may exist.  This is ARM, after all.
class R_ARM_THM_JUMP24(R_ARM_THM_CALL):
    pass

class R_ARM_THM_JUMP19(R_ARM_THM_CALL):
    pass

class R_ARM_THM_JUMP6(R_ARM_THM_CALL):
    pass
