from . import generic

arch = 'AARCH64'

R_AARCH64_COPY = generic.GenericCopyReloc
R_AARCH64_GLOB_DAT = generic.GenericJumpslotReloc
R_AARCH64_JUMP_SLOT = generic.GenericJumpslotReloc
R_AARCH64_RELATIVE = generic.GenericRelativeReloc
R_AARCH64_TLS_DTPREL64 = generic.GenericTLSDoffsetReloc
R_AARCH64_TLS_DTPMOD64 = generic.GenericTLSModIdReloc
R_AARCH64_TLS_TPREL64 = generic.GenericTLSOffsetReloc
