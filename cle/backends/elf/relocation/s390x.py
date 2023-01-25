from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericIRelativeReloc,
    GenericJumpslotReloc,
    GenericRelativeReloc,
    GenericTLSOffsetReloc,
)

arch = "S390X"


class R_390_GLOB_DAT(GenericJumpslotReloc):
    pass


class R_390_JMP_SLOT(GenericJumpslotReloc):
    pass


class R_390_RELATIVE(GenericRelativeReloc):
    pass


class R_390_64(GenericAbsoluteAddendReloc):
    pass


class R_390_TLS_TPOFF(GenericTLSOffsetReloc):
    pass


class R_390_IRELATIVE(GenericIRelativeReloc):
    pass


class R_390_COPY(GenericCopyReloc):
    pass
