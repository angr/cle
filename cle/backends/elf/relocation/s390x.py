from . import generic

arch = 'S390X'


class R_390_GLOB_DAT(generic.GenericJumpslotReloc):
    pass


class R_390_JMP_SLOT(generic.GenericJumpslotReloc):
    pass


class R_390_RELATIVE(generic.GenericRelativeReloc):
    pass


class R_390_64(generic.GenericAbsoluteAddendReloc):
    pass


class R_390_TLS_TPOFF(generic.GenericTLSOffsetReloc):
    pass


class R_390_IRELATIVE(generic.GenericIRelativeReloc):
    pass


class R_390_COPY(generic.GenericCopyReloc):
    pass
