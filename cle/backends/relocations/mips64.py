from . import generic
from . import generic_elf

arch = 'MIPS64'

class R_MIPS_64(generic.GenericAbsoluteAddendReloc):
    pass

class R_MIPS_REL32(generic.GenericRelativeReloc):
    pass

class R_MIPS_COPY(generic.GenericCopyReloc):
    pass

class R_MIPS_TLS_DTPMOD64(generic_elf.GenericTLSModIdReloc):
    pass

class R_MIPS_TLS_DTPREL64(generic_elf.GenericTLSDoffsetReloc):
    pass

class R_MIPS_TLS_TPREL64(generic_elf.GenericTLSOffsetReloc):
    pass
