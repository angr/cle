from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericIRelativeReloc,
    GenericJumpslotReloc,
    GenericPCRelativeAddendReloc,
    GenericRelativeReloc,
    GenericTLSDoffsetReloc,
    GenericTLSModIdReloc,
    GenericTLSOffsetReloc,
)

arch = "X86"


class R_386_32(GenericAbsoluteAddendReloc):
    pass


class R_386_PC32(GenericPCRelativeAddendReloc):
    pass


class R_386_COPY(GenericCopyReloc):
    pass


class R_386_GLOB_DAT(GenericJumpslotReloc):
    pass


class R_386_JMP_SLOT(GenericJumpslotReloc):
    pass


class R_386_RELATIVE(GenericRelativeReloc):
    pass


class R_386_IRELATIVE(GenericIRelativeReloc):
    pass


class R_386_TLS_DTPMOD32(GenericTLSModIdReloc):
    pass


class R_386_TLS_TPOFF(GenericTLSOffsetReloc):
    pass


class R_386_TLS_DTPOFF32(GenericTLSDoffsetReloc):
    pass
