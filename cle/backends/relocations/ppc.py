from . import generic
from . import generic_elf

# http://www.polyomino.org.uk/publications/2011/Power-Arch-32-bit-ABI-supp-1.0-Unified.pdf
arch = 'PPC32'

class R_PPC_ADDR32(generic.GenericAbsoluteAddendReloc):
    pass

class R_PPC_COPY(generic.GenericCopyReloc):
    pass

class R_PPC_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_PPC_JMP_SLOT(generic.GenericJumpslotReloc):
    pass

class R_PPC_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_PPC_DTPMOD32(generic_elf.GenericTLSModIdReloc):
    pass

class R_PPC_DTPREL32(generic_elf.GenericTLSDoffsetReloc):
    pass

class R_PPC_TPREL32(generic_elf.GenericTLSOffsetReloc):
    pass
