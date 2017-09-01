from . import generic

arch = 'MIPS64'

class R_MIPS_64(generic.GenericAbsoluteAddendReloc):
    pass

class R_MIPS_REL32(generic.GenericRelativeReloc):
    pass

class R_MIPS_COPY(generic.GenericCopyReloc):
    pass

class R_MIPS_TLS_DTPMOD64(generic.GenericTLSModIdReloc):
    pass

class R_MIPS_TLS_DTPREL64(generic.GenericTLSDoffsetReloc):
    pass

class R_MIPS_TLS_TPREL64(generic.GenericTLSOffsetReloc):
    pass
