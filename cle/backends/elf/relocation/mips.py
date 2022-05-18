from . import generic

arch = 'MIPS32'

class R_MIPS_32(generic.GenericAbsoluteAddendReloc):
    pass

class R_MIPS_REL32(generic.GenericRelativeReloc):
    pass

class R_MIPS_JUMP_SLOT(generic.GenericAbsoluteReloc):
    pass

class R_MIPS_GLOB_DAT(generic.GenericAbsoluteReloc):
    pass

class R_MIPS_TLS_DTPMOD32(generic.GenericTLSModIdReloc):
    pass

class R_MIPS_TLS_TPREL32(generic.GenericTLSOffsetReloc):
    pass

class R_MIPS_TLS_DTPREL32(generic.GenericTLSDoffsetReloc):
    pass

class R_MIPS_HI16(generic.GenericAbsoluteReloc):
    def relocate(self):
        if not self.resolved:
            return False

        self.owner.memory.pack_word(self.dest_addr, self.value >> 16, size=2)
        return True

class R_MIPS_LO16(generic.GenericAbsoluteReloc):
    def relocate(self):
        if not self.resolved:
            return False

        self.owner.memory.pack_word(self.dest_addr, self.value & 0xffff, size=2)
        return True
