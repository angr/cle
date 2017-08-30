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
