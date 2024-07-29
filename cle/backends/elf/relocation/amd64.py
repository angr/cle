from __future__ import annotations

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
    RelocTruncate32Mixin,
)

arch = "AMD64"


class R_X86_64_64(GenericAbsoluteAddendReloc):
    pass


class R_X86_64_COPY(GenericCopyReloc):
    pass


class R_X86_64_RELATIVE(GenericRelativeReloc):
    pass


class R_X86_64_IRELATIVE(GenericIRelativeReloc):
    pass


class R_X86_64_GLOB_DAT(GenericJumpslotReloc):
    pass


class R_X86_64_JUMP_SLOT(GenericJumpslotReloc):
    pass


class R_X86_64_DTPMOD64(GenericTLSModIdReloc):
    pass


class R_X86_64_DTPOFF64(GenericTLSDoffsetReloc):
    pass


class R_X86_64_TPOFF64(GenericTLSOffsetReloc):
    pass


class R_X86_64_PC32(RelocTruncate32Mixin, GenericPCRelativeAddendReloc):
    check_sign_extend = True


class R_X86_64_32(RelocTruncate32Mixin, GenericAbsoluteAddendReloc):
    check_zero_extend = True


class R_X86_64_32S(RelocTruncate32Mixin, GenericAbsoluteAddendReloc):
    check_sign_extend = True


class R_X86_64_PLT32(RelocTruncate32Mixin, GenericPCRelativeAddendReloc):
    check_sign_extend = True


class R_X86_64_GOTPCREL(RelocGOTMixin, RelocTruncate32Mixin, GenericPCRelativeAddendReloc):
    check_sign_extend = True


class R_X86_64_GOTPCRELX(RelocGOTMixin, RelocTruncate32Mixin, GenericPCRelativeAddendReloc):
    check_sign_extend = True


class R_X86_64_REX_GOTPCRELX(RelocGOTMixin, RelocTruncate32Mixin, GenericPCRelativeAddendReloc):
    check_sign_extend = True
