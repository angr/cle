from __future__ import annotations

from .generic import (
    GenericAbsoluteAddendReloc,
    GenericCopyReloc,
    GenericRelativeReloc,
    GenericTLSDoffsetReloc,
    GenericTLSModIdReloc,
    GenericTLSOffsetReloc,
)

arch = "MIPS64"


class R_MIPS_64(GenericAbsoluteAddendReloc):
    pass


class R_MIPS_REL32(GenericRelativeReloc):
    pass


class R_MIPS_COPY(GenericCopyReloc):
    pass


class R_MIPS_TLS_DTPMOD64(GenericTLSModIdReloc):
    pass


class R_MIPS_TLS_DTPREL64(GenericTLSDoffsetReloc):
    pass


class R_MIPS_TLS_TPREL64(GenericTLSOffsetReloc):
    pass
