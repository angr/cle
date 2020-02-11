import logging
from . import generic
from .elfreloc import ELFReloc

l = logging.getLogger(name=__name__)

# http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf
arch = 'PPC64'

class R_PPC64_JMP_SLOT(ELFReloc):
    def relocate(self):
        if self.owner.is_ppc64_abiv1:
            # R_PPC64_JMP_SLOT
            # http://osxr.org/glibc/source/sysdeps/powerpc/powerpc64/dl-machine.h?v=glibc-2.15#0405
            # copy an entire function descriptor struct
            addr = self.resolvedby.owner.memory.unpack_word(self.resolvedby.relative_addr)
            toc = self.resolvedby.owner.memory.unpack_word(self.resolvedby.relative_addr + 8)
            aux = self.resolvedby.owner.memory.unpack_word(self.resolvedby.relative_addr + 16)
            self.owner.memory.pack_word(self.relative_addr, addr)
            self.owner.memory.pack_word(self.relative_addr + 8, toc)
            self.owner.memory.pack_word(self.relative_addr + 16, aux)
        else:
            self.owner.memory.pack_word(self.relative_addr, self.resolvedby.rebased_addr)
        return True

class R_PPC64_RELATIVE(generic.GenericRelativeReloc):
    pass

class R_PPC64_IRELATIVE(generic.GenericIRelativeReloc):
    pass

class R_PPC64_ADDR64(generic.GenericAbsoluteAddendReloc):
    pass

class R_PPC64_GLOB_DAT(generic.GenericJumpslotReloc):
    pass

class R_PPC64_DTPMOD64(generic.GenericTLSModIdReloc):
    pass

class R_PPC64_DTPREL64(generic.GenericTLSDoffsetReloc):
    pass

class R_PPC64_TPREL64(generic.GenericTLSOffsetReloc):
    pass
