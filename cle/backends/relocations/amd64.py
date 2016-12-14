from . import generic
from . import generic_elf

arch = 'AMD64'

R_X86_64_64 = generic.GenericAbsoluteAddendReloc
R_X86_64_COPY = generic.GenericCopyReloc
R_X86_64_GLOB_DAT = generic.GenericJumpslotReloc
R_X86_64_JUMP_SLOT = generic.GenericJumpslotReloc
R_X86_64_RELATIVE = generic.GenericRelativeReloc
R_X86_64_IRELATIVE = generic_elf.GenericIRelativeReloc

R_X86_64_DTPMOD64 = generic_elf.GenericTLSModIdReloc
R_X86_64_DTPOFF64 = generic_elf.GenericTLSDoffsetReloc
R_X86_64_TPOFF64 = generic_elf.GenericTLSOffsetReloc

class R_X86_64_PC32(generic.RelocTruncate32Mixin, generic.GenericPCRelativeAddendReloc):
    check_sign_extend = True

class R_X86_64_32(generic.RelocTruncate32Mixin, generic.GenericAbsoluteAddendReloc):
    check_zero_extend = True

class R_X86_64_32S(generic.RelocTruncate32Mixin, generic.GenericAbsoluteAddendReloc):
    check_sign_extend = True
