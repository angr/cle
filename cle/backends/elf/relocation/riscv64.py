"""
Relocations for RISCV64

Reference:
1. https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#relocations
2. https://docs.riscv.org/reference/isa/_attachments/riscv-unprivileged.pdf

"""

from __future__ import annotations

import logging

from .elfreloc import ELFReloc
from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericIRelativeReloc,
    GenericJumpslotReloc,
    RelocGOTMixin,
    RelocTruncate32Mixin,
)

log = logging.getLogger(name=__name__)


class R_RISCV_NONE(ELFReloc):
    """
    Relocation Type: 0
    Calculation: None
    """

    def relocate(self):
        return True


class R_RISCV_32(RelocTruncate32Mixin, GenericAbsoluteAddendReloc):
    """
    Relocation Type: 1
    Calculation: S + A
    """


class R_RISCV_64(GenericAbsoluteAddendReloc):
    """
    Relocation Type: 2
    Calculation: S + A
    """


class R_RISCV_RELATIVE(ELFReloc):
    """
    Relocation Type: 3
    Calculation: B + A
    """

    AUTO_HANDLE_NONE = True

    @property
    def value(self) -> int:
        return self.owner.mapped_base + self.addend


class R_RISCV_COPY(GenericCopyReloc):
    """
    Relocation Type: 4
    Calculation: None
    """


class R_RISCV_JUMP_SLOT(GenericJumpslotReloc):
    """
    Relocation Type: 5
    Calculation: S
    """


class R_RISCV_BRANCH(ELFReloc):
    """
    Relocation Type: 16
    Calculation: S + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value

        if val & 0x1:
            log.warning("Unaligned BRANCH relocation")

        imm = val >> 1
        if not -(1 << 12) <= imm < (1 << 12):
            log.warning("BRANCH relocation out of range")

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)

        instr &= ~((1 << 31) | (0x3F << 25) | (0xF << 8) | (1 << 7))  # imm[12]  # imm[10:5]  # imm[4:1]  # imm[11]

        instr |= (
            ((imm >> 11) & 0x1) << 31  # imm[12]
            | ((imm >> 4) & 0x3F) << 25  # imm[10:5]
            | ((imm >> 0) & 0xF) << 8  # imm[4:1]
            | ((imm >> 10) & 0x1) << 7  # imm[11]
        )

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_JAL(ELFReloc):
    """
    Relocation Type: 17
    Calculation: S + A - P
    """

    AUTO_HANDLE_NONE = False

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        if not -(1 << 20) <= val < (1 << 20):
            log.warning("JAL relocation out of range")

        imm = val >> 1

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= 0xFFF

        instr |= (
            ((imm >> 19) & 0x1) << 31  # imm[20]
            | ((imm >> 0) & 0x3FF) << 21  # imm[10:1]
            | ((imm >> 10) & 0x1) << 20  # imm[11]
            | ((imm >> 11) & 0xFF) << 12  # imm[19:12]
        )

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_CALL_PLT(ELFReloc):
    """
    Relocation Type: 19
    Calculation: S + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        # U + I Type instruction pair
        hi20 = (val + 0x800) >> 12
        lo12 = val & 0xFFF

        instr_hi = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr_hi &= 0x00000FFF
        instr_hi |= (hi20 & 0xFFFFF) << 12
        self.owner.memory.pack_word(self.relative_addr, instr_hi, size=4)

        instr_lo = self.owner.memory.unpack_word(self.relative_addr + 4, size=4)
        instr_lo &= 0x000FFFFF
        instr_lo |= (lo12 & 0xFFF) << 20
        self.owner.memory.pack_word(self.relative_addr + 4, instr_lo, size=4)

        return True


class R_RISCV_CALL(R_RISCV_CALL_PLT):
    """
    Relocation Type: 18
    Calculation: S + A - P
    """

    def relocate(self):
        log.debug("R_RISCV_CALL encountered, treating as CALL_PLT")
        return super().relocate()


class R_RISCV_GOT_HI20(RelocGOTMixin, ELFReloc):
    """
    Relocation Type: 20
    Calculation: G + GOT + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def resolve(self, obj, extern_object=None):
        return RelocGOTMixin.resolve(self, symbol=obj, extern_object=extern_object)

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        hi20 = (val + 0x800) >> 12

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= 0x00000FFF
        instr |= (hi20 & 0xFFFFF) << 12

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_PCREL_HI20(ELFReloc):
    """
    Relocation Type: 23
    Calculation: S + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        hi20 = (val + 0x800) >> 12

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= 0x00000FFF
        instr |= (hi20 & 0xFFFFF) << 12

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


def _find_paired_hi20(self):
    # TODO: We don't implement R_RISCV_TLS_GOT_HI20 now
    label_addr = self.resolvedby.rebased_addr
    for rr in self.owner.relocs:
        if rr.rebased_addr != label_addr:
            continue
        if isinstance(rr, (R_RISCV_PCREL_HI20, R_RISCV_GOT_HI20)):
            return rr
    return None


class R_RISCV_PCREL_LO12_I(ELFReloc):
    """
    Relocation Type: 24
    """

    def relocate(self):
        if not self.resolved or self.resolvedby is None:
            return False

        hi = _find_paired_hi20(self)
        if hi is None or not hi.resolved:
            log.warning("PCREL_LO12_I without matching HI20 at %#x", self.resolvedby.rebased_addr)
            return False

        off = hi.value
        lo12 = (off + self.addend) & 0xFFF

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~(0xFFF << 20)
        instr |= lo12 << 20
        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_PCREL_LO12_S(ELFReloc):
    """
    Relocation Type: 25
    """

    def relocate(self):
        if not self.resolved or self.resolvedby is None:
            return False

        hi = _find_paired_hi20(self)
        if hi is None or not hi.resolved:
            log.warning("PCREL_LO12_S without matching HI20 at %#x", self.resolvedby.rebased_addr)
            return False

        off = hi.value
        lo12 = (off + self.addend) & 0xFFF
        imm_11_5 = (lo12 >> 5) & 0x7F
        imm_4_0 = lo12 & 0x1F

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~((0x7F << 25) | (0x1F << 7))
        instr |= (imm_11_5 << 25) | (imm_4_0 << 7)
        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_HI20(GenericAbsoluteAddendReloc):
    """
    Relocation Type: 26
    Calculation: S + A
    """

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        hi20 = (val + 0x800) >> 12
        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr = (instr & 0x00000FFF) | ((hi20 & 0xFFFFF) << 12)
        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_LO12_I(ELFReloc):
    """
    Relocation Type: 27
    Calculation: S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        lo12 = val & 0xFFF

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~(0xFFF << 20)
        instr |= lo12 << 20

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_LO12_S(ELFReloc):
    """
    Relocation Type: 28
    Calculation: S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        lo12 = val & 0xFFF

        instr = self.owner.memory.unpack_word(self.relative_addr, size=4)
        instr &= ~((0x7F << 25) | (0x1F << 7))
        instr |= ((lo12 >> 5) & 0x7F) << 25
        instr |= (lo12 & 0x1F) << 7

        self.owner.memory.pack_word(self.relative_addr, instr, size=4)
        return True


class R_RISCV_ADD8(ELFReloc):
    """
    Relocation Type: 33
    Calculation: V + S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=1)
        new_val = (V + self.value) & 0xFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=1)
        return True


class R_RISCV_ADD16(ELFReloc):
    """
    Relocation Type: 34
    Calculation: V + S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=2)
        new_val = (V + self.value) & 0xFFFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=2)
        return True


class R_RISCV_ADD32(ELFReloc):
    """
    Relocation Type: 35
    Calculation: V + S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=4)
        new_val = (V + self.value) & 0xFFFFFFFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=4)
        return True


class R_RISCV_ADD64(ELFReloc):
    """
    Relocation Type: 36
    Calculation: V + S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=8)
        new_val = (V + self.value) & 0xFFFFFFFFFFFFFFFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=8)
        return True


class R_RISCV_SUB8(ELFReloc):
    """
    Relocation Type: 37
    Calculation: V - S - A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=1)
        new_val = (V - self.value) & 0xFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=1)
        return True


class R_RISCV_SUB16(ELFReloc):
    """
    Relocation Type: 38
    Calculation: V - S - A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=2)
        new_val = (V - self.value) & 0xFFFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=2)
        return True


class R_RISCV_SUB32(ELFReloc):
    """
    Relocation Type: 39
    Calculation: V - S - A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=4)
        new_val = (V - self.value) & 0xFFFFFFFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=4)
        return True


class R_RISCV_SUB64(ELFReloc):
    """
    Relocation Type: 40
    Calculation: V - S - A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0
        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        v = self.owner.memory.unpack_word(self.relative_addr, size=8)
        new_val = (v - self.value) & 0xFFFFFFFFFFFFFFFF
        self.owner.memory.pack_word(self.relative_addr, new_val, size=8)
        return True


class R_RISCV_ALIGN(ELFReloc):
    """
    Relocation Type: 43
    Calculation: None
    """

    AUTO_HANDLE_NONE = True

    def relocate(self):
        return True


class R_RISCV_RVC_BRANCH(ELFReloc):
    """
    Relocation Type: 44
    Calculation: S + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value

        # C.B* offsets are multiples of 2
        if val & 0x1:
            log.warning("Unaligned RVC branch target")

        imm = val >> 1

        if not -256 <= val < 256:
            log.warning("RVC branch out of range")

        instr = self.owner.memory.unpack_word(self.relative_addr, size=2)
        instr &= ~0x1C7C
        instr |= (
            ((imm >> 7) & 0x1) << 12  # val[8]
            | ((imm >> 2) & 0x3) << 10  # val[4:3]
            | ((imm >> 5) & 0x3) << 5  # val[7:6]
            | ((imm >> 0) & 0x3) << 3  # val[2:1]
            | ((imm >> 4) & 0x1) << 2  # val[5]
        )
        self.owner.memory.pack_word(self.relative_addr, instr, size=2)
        return True


class R_RISCV_RVC_JUMP(ELFReloc):
    """
    Relocation Type: 45
    Calculation: S + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        if not self.resolved:
            return False

        val = self.value
        imm = val >> 1

        instr = self.owner.memory.unpack_word(self.relative_addr, size=2)

        instr &= ~0x1FFC
        instr |= (
            ((imm >> 10) & 1) << 12  # imm[11]
            | ((imm >> 3) & 1) << 11  # imm[4]
            | ((imm >> 7) & 0x3) << 9  # imm[9:8]
            | ((imm >> 9) & 1) << 8  # imm[10]
            | ((imm >> 5) & 1) << 7  # imm[6]
            | ((imm >> 6) & 1) << 6  # imm[7]
            | ((imm >> 0) & 0x7) << 3  # imm[3:1]
            | ((imm >> 4) & 1) << 2  # imm[5]
        )
        self.owner.memory.pack_word(self.relative_addr, instr, size=2)
        return True


class R_RISCV_RELAX(ELFReloc):
    """
    Relocation Type: 51
    Calculation: None
    """

    AUTO_HANDLE_NONE = True

    def relocate(self):
        return True


class R_RISCV_SUB6(ELFReloc):
    """
    Relocation Type: 52
    Calculation: V - S - A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return S + A

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=1)
        old_6bit_val = V & 0x3F
        new_6bit_val = (old_6bit_val - self.value) & 0x3F
        new_val = (V & 0xC0) | new_6bit_val
        self.owner.memory.pack_word(self.relative_addr, new_val, size=1)
        return True


class R_RISCV_SET6(ELFReloc):
    """
    Relocation Type: 53
    Calculation: S + A
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        return (S + A) & 0x3F

    def relocate(self):
        if not self.resolved:
            return False

        V = self.owner.memory.unpack_word(self.relative_addr, size=1)
        new_val = (V & 0xC0) | self.value
        self.owner.memory.pack_word(self.relative_addr, new_val, size=1)
        return True


class R_RISCV_SET8(GenericAbsoluteAddendReloc):
    """
    Relocation Type: 54
    Calculation: S + A
    """

    def relocate(self):
        if not self.resolved:
            return False

        self.owner.memory.pack_word(self.relative_addr, self.value & 0xFF, size=1)
        return True


class R_RISCV_SET16(GenericAbsoluteAddendReloc):
    """
    Relocation Type: 55
    Calculation: S + A
    """

    def relocate(self):
        if not self.resolved:
            return False

        self.owner.memory.pack_word(self.relative_addr, self.value & 0xFFFF, size=2)
        return True


class R_RISCV_SET32(RelocTruncate32Mixin, GenericAbsoluteAddendReloc):
    """
    Relocation Type: 56
    Calculation: S + A
    """


class R_RISCV_32_PCREL(ELFReloc):
    """
    Relocation Type: 57
    Calculation: S + A - P
    """

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            return 0

        S = self.resolvedby.rebased_addr
        A = self.addend
        P = self.rebased_addr
        return S + A - P

    def relocate(self):
        val = self.value
        self.owner.memory.pack_word(self.relative_addr, val & 0xFFFFFFFF, size=4)
        return True


class R_RISCV_IRELATIVE(GenericIRelativeReloc):
    """
    Relocation Type: 58
    Calculation: ifunc_resolver(B + A)
    """


class R_RISCV_SET_ULEB128(ELFReloc):
    """
    Relocation Type: 60
    Calculation: S + A
    """

    AUTO_HANDLE_NONE = True

    def relocate(self):
        return True


class R_RISCV_SUB_ULEB128(ELFReloc):
    """
    Relocation Type: 61
    Calculation: V - S - A
    """

    AUTO_HANDLE_NONE = True

    def relocate(self):
        return True


relocation_table_riscv64 = {
    0: R_RISCV_NONE,
    1: R_RISCV_32,
    2: R_RISCV_64,
    3: R_RISCV_RELATIVE,
    4: R_RISCV_COPY,
    5: R_RISCV_JUMP_SLOT,
    # 6: R_RISCV_TLS_DTPMOD32,
    # 7: R_RISCV_TLS_DTPMOD64,
    # 8: R_RISCV_TLS_DTPREL32,
    # 9: R_RISCV_TLS_DTPREL64,
    # 10: R_RISCV_TLS_TPREL32,
    # 11: R_RISCV_TLS_TPREL64,
    # 12: R_RISCV_TLSDESC
    16: R_RISCV_BRANCH,
    17: R_RISCV_JAL,
    18: R_RISCV_CALL,
    19: R_RISCV_CALL_PLT,
    20: R_RISCV_GOT_HI20,
    # 21: R_RISCV_TLS_GOT_HI20,
    # 22: R_RISCV_TLS_GD_HI20,
    23: R_RISCV_PCREL_HI20,
    24: R_RISCV_PCREL_LO12_I,
    25: R_RISCV_PCREL_LO12_S,
    26: R_RISCV_HI20,
    27: R_RISCV_LO12_I,
    28: R_RISCV_LO12_S,
    # 29: R_RISCV_TPREL_HI20,
    # 30: R_RISCV_TPREL_LO12_I,
    # 31: R_RISCV_TPREL_LO12_S,
    # 32: R_RISCV_TPREL_ADD,
    33: R_RISCV_ADD8,
    34: R_RISCV_ADD16,
    35: R_RISCV_ADD32,
    36: R_RISCV_ADD64,
    37: R_RISCV_SUB8,
    38: R_RISCV_SUB16,
    39: R_RISCV_SUB32,
    40: R_RISCV_SUB64,
    # 41: R_RISCV_GOT32_PCREL,
    # 42: Reserved
    43: R_RISCV_ALIGN,
    44: R_RISCV_RVC_BRANCH,
    45: R_RISCV_RVC_JUMP,
    # 46-50: Reserved
    51: R_RISCV_RELAX,
    52: R_RISCV_SUB6,
    53: R_RISCV_SET6,
    54: R_RISCV_SET8,
    55: R_RISCV_SET16,
    56: R_RISCV_SET32,
    57: R_RISCV_32_PCREL,
    58: R_RISCV_IRELATIVE,
    # 59: R_RISCV_PLT32,
    60: R_RISCV_SET_ULEB128,
    61: R_RISCV_SUB_ULEB128,
    # 62: R_RISCV_TLSDESC_HI20,
    # 63: R_RISCV_TLSDESC_LOAD_LO12,
    # 64: R_RISCV_TLSDESC_ADD_LO12,
    # 65: R_RISCV_TLSDESC_CALL,
    # 66-190: Reserved
    # 191: R_RISCV_VENDOR,
    # 192-255: Reserved
}


__all__ = ("relocation_table_riscv64",)
