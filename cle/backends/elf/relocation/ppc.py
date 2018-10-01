import logging
from . import generic

l = logging.getLogger('cle.backends.elf.relocations.ppc')
arch = 'PPC32'

class R_PPC_ADDR32(generic.GenericAbsoluteAddendReloc):
    pass

class R_PPC_COPY(generic.GenericCopyReloc):
    pass

class R_PPC_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_PPC_JMP_SLOT(generic.GenericJumpslotReloc):
    def relocate(self, solist, bypass_compatibility=False):
        if 'DT_PPC_GOT' not in self.owner._dynamic and 'DT_LOPROC' not in self.owner._dynamic:
            l.error("This binary is relocated incorrectly. See https://github.com/angr/cle/issues/142 for details.")
        return super(R_PPC_JMP_SLOT, self).relocate(solist, bypass_compatibility=bypass_compatibility)

class R_PPC_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_PPC_DTPMOD32(generic.GenericTLSModIdReloc):
    pass

class R_PPC_DTPREL32(generic.GenericTLSDoffsetReloc):
    pass

class R_PPC_TPREL32(generic.GenericTLSOffsetReloc):
    pass
