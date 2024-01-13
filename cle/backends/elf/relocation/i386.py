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
    RelocGOTMixin,
)

arch = "X86"


class R_386_32(GenericAbsoluteAddendReloc):
    """
    Value: 1
    Field: word32
    Calculation: S + A
    """
    pass


class R_386_PC32(GenericPCRelativeAddendReloc):
    """
    Value: 2
    Field: word32
    Calculation: S + A - P
    """
    pass


class R_386_COPY(GenericCopyReloc):
    """
    Value: 5
    Field:
    Calculation:
    """
    pass


class R_386_GLOB_DAT(GenericJumpslotReloc):
    """
    Value: 6
    Field: word32
    Calculation: S
    """
    pass


class R_386_JMP_SLOT(GenericJumpslotReloc):
    """
    Value: 7
    Field: word32
    Calculation: S
    """
    pass


class R_386_RELATIVE(GenericRelativeReloc):
    """
    Value: 8
    Field: word32
    Calculation: B + A
    """
    pass


class R_386_IRELATIVE(GenericIRelativeReloc):
    """
    Value: 42
    Field: word32
    Calculation: indirect (B + A)
    """
    pass


class R_386_TLS_DTPMOD32(GenericTLSModIdReloc):
    """
    Value: 35
    Field: word32
    Calculation: 
    """
    pass


class R_386_TLS_TPOFF(GenericTLSOffsetReloc):
    """
    Value: 14
    Field: word32
    Calculation: 
    """
    pass


class R_386_TLS_DTPOFF32(GenericTLSDoffsetReloc):
    """
    Value: 36
    Field: word32
    Calculation: 
    """
    pass


class R_386_PLT32(GenericPCRelativeAddendReloc):
    """
    Value: 4
    Field: word32
    Calculation: L + A - P
    """
    pass


class R_386_GOTPC(GenericPCRelativeAddendReloc, RelocGOTMixin):
    """
    Value: 10
    Field: word32
    Calculation: GOT + A - P
    """
    pass
