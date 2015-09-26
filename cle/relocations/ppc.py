from . import generic

arch = 'PPC32'

R_PPC_ADDR32 = generic.GenericAbsoluteAddendReloc
R_PPC_COPY = generic.GenericCopyReloc
R_PPC_GLOB_DAT = generic.GenericJumpslotReloc
R_PPC_JMP_SLOT = generic.GenericJumpslotReloc
R_PPC_RELATIVE = generic.GenericRelativeReloc
R_PPC_DTPMOD32 = generic.GenericTLSModIdReloc
R_PPC_DTPREL32 = generic.GenericTLSDoffsetReloc
R_PPC_TPREL32 = generic.GenericTLSOffsetReloc
