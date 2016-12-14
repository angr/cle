from . import generic
from . import generic_elf

arch = 'X86'

R_386_32 = generic.GenericAbsoluteAddendReloc
R_386_PC32 = generic.GenericPCRelativeAddendReloc
R_386_COPY = generic.GenericCopyReloc
R_386_GLOB_DAT = generic.GenericJumpslotReloc
R_386_JMP_SLOT = generic.GenericJumpslotReloc
R_386_RELATIVE = generic.GenericRelativeReloc
R_386_IRELATIVE = generic_elf.GenericIRelativeReloc

R_386_TLS_DTPMOD32 = generic_elf.GenericTLSModIdReloc
R_386_TLS_TPOFF = generic_elf.GenericTLSOffsetReloc
R_386_TLS_DTPOFF32 = generic_elf.GenericTLSDoffsetReloc
