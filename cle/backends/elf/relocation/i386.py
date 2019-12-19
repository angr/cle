import logging
from . import generic

l = logging.getLogger(name=__name__)
arch = 'X86'

class R_386_32(generic.GenericAbsoluteAddendReloc):
    pass

class R_386_PC32(generic.GenericPCRelativeAddendReloc):
    pass

class R_386_COPY(generic.GenericCopyReloc):
    pass

class R_386_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_386_JMP_SLOT(generic.GenericJumpslotReloc):
    pass

class R_386_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_386_IRELATIVE(generic.GenericIRelativeReloc):
    pass

class R_386_TLS_DTPMOD32(generic.GenericTLSModIdReloc):
    pass

class R_386_TLS_TPOFF(generic.GenericTLSOffsetReloc):
    pass

class R_386_TLS_DTPOFF32(generic.GenericTLSDoffsetReloc):
    pass
