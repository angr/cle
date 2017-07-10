from . import generic
from . import generic_elf
from . import Relocation
from ...address_translator import AT

# http://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf
arch = 'PPC64'

class R_PPC64_JMP_SLOT(Relocation):
    def relocate(self, solist, bypass_compatibility=False):
        if not self.resolve_symbol(solist, bypass_compatibility):
            return False

        if self.owner_obj.is_ppc64_abiv1:
            # R_PPC64_JMP_SLOT
            # http://osxr.org/glibc/source/sysdeps/powerpc/powerpc64/dl-machine.h?v=glibc-2.15#0405
            # copy an entire function descriptor struct
            addr = self.resolvedby.owner_obj.memory.read_addr_at(
                AT.from_lva(self.resolvedby.addr, self.resolvedby.owner_obj).to_rva())
            toc = self.resolvedby.owner_obj.memory.read_addr_at(
                AT.from_lva(self.resolvedby.addr, self.resolvedby.owner_obj).to_rva() + 8)
            aux = self.resolvedby.owner_obj.memory.read_addr_at(
                AT.from_lva(self.resolvedby.addr, self.resolvedby.owner_obj).to_rva() + 16)
            self.owner_obj.memory.write_addr_at(AT.from_lva(self.addr, self.owner_obj).to_rva(), addr)
            self.owner_obj.memory.write_addr_at(AT.from_lva(self.addr, self.owner_obj).to_rva() + 8, toc)
            self.owner_obj.memory.write_addr_at(AT.from_lva(self.addr, self.owner_obj).to_rva() + 16, aux)
        else:
            self.owner_obj.memory.write_addr_at(
                AT.from_lva(self.addr, self.owner_obj).to_rva(), self.resolvedby.rebased_addr)
        return True

R_PPC64_RELATIVE = generic.GenericRelativeReloc
R_PPC64_IRELATIVE = generic_elf.GenericIRelativeReloc
R_PPC64_ADDR64 = generic.GenericAbsoluteAddendReloc
R_PPC64_GLOB_DAT = generic.GenericJumpslotReloc

R_PPC64_DTPMOD64 = generic_elf.GenericTLSModIdReloc
R_PPC64_DTPREL64 = generic_elf.GenericTLSDoffsetReloc
R_PPC64_TPREL64 = generic_elf.GenericTLSOffsetReloc
