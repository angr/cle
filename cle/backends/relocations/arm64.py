from . import generic
from . import generic_elf

# http://infocenter.arm.com/help/topic/com.arm.doc.ihi0056b/IHI0056B_aaelf64.pdf
arch = 'AARCH64'

class R_AARCH64_ABS64(generic.GenericAbsoluteAddendReloc):
    pass

class R_AARCH64_COPY(generic.GenericCopyReloc):
    pass

class R_AARCH64_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_AARCH64_JUMP_SLOT(generic.GenericJumpslotReloc):
    pass

class R_AARCH64_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_AARCH64_IRELATIVE(generic_elf.GenericIRelativeReloc):
    pass

class R_AARCH64_TLS_DTPREL(generic_elf.GenericTLSDoffsetReloc):
    pass

class R_AARCH64_TLS_DTPMOD(generic_elf.GenericTLSModIdReloc):
    pass

class R_AARCH64_TLS_TPREL(generic_elf.GenericTLSOffsetReloc):
    pass
