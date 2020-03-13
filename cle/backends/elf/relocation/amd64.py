import logging
from . import generic

l = logging.getLogger(name=__name__)
arch = 'AMD64'

class R_X86_64_64(generic.GenericAbsoluteAddendReloc):
    pass

class R_X86_64_COPY(generic.GenericCopyReloc):
    pass

class R_X86_64_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_X86_64_IRELATIVE(generic.GenericIRelativeReloc):
    pass

class R_X86_64_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_X86_64_JUMP_SLOT(generic.GenericJumpslotReloc):
    pass

class R_X86_64_DTPMOD64(generic.GenericTLSModIdReloc):
    pass

class R_X86_64_DTPOFF64(generic.GenericTLSDoffsetReloc):
    pass

class R_X86_64_TPOFF64(generic.GenericTLSOffsetReloc):
    pass

class R_X86_64_PC32(generic.RelocTruncate32Mixin, generic.GenericPCRelativeAddendReloc):
    check_sign_extend = True

class R_X86_64_32(generic.RelocTruncate32Mixin, generic.GenericAbsoluteAddendReloc):
    check_zero_extend = True

class R_X86_64_32S(generic.RelocTruncate32Mixin, generic.GenericAbsoluteAddendReloc):
    check_sign_extend = True

class R_X86_64_PLT32(generic.RelocTruncate32Mixin, generic.GenericPCRelativeAddendReloc):
    check_sign_extend = True

class R_X86_64_GOTPCREL(generic.RelocGOTMixin, generic.RelocTruncate32Mixin, generic.GenericPCRelativeAddendReloc):
    check_sign_extend = True

class R_X86_64_GOTPCRELX(generic.RelocGOTMixin, generic.RelocTruncate32Mixin, generic.GenericPCRelativeAddendReloc):
    check_sign_extend = True

class R_X86_64_REX_GOTPCRELX(generic.RelocGOTMixin, generic.RelocTruncate32Mixin, generic.GenericPCRelativeAddendReloc):
    check_sign_extend = True