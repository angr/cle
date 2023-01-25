from .generic import (
    GenericAbsoluteAddendReloc,
    GenericAbsoluteReloc,
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
