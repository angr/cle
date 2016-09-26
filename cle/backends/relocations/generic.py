from ...errors import CLEOperationError
from . import Relocation

import logging
l = logging.getLogger('cle.relocations.generic')

class GenericAbsoluteReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr

class GenericAbsoluteAddendReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend

class GenericJumpslotReloc(Relocation):
    @property
    def value(self):
        if self.is_rela:
            return self.resolvedby.rebased_addr + self.addend
        else:
            return self.resolvedby.rebased_addr

class GenericRelativeReloc(Relocation):
    @property
    def value(self):
        return self.owner_obj.rebase_addr + self.addend

    def resolve_symbol(self, solist, bypass_compatibility=False):
        self.resolve(None)
        return True

class GenericCopyReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr)

class GenericIRelativeReloc(Relocation):
    def relocate(self, solist, bypass_compatibility=False):
        if self.symbol.type == 'STT_NOTYPE':
            self.owner_obj.irelatives.append((self.owner_obj.rebase_addr + self.addend, self.addr))
            self.resolve(None)
            return True

        if not self.resolve_symbol(solist, bypass_compatibility):
            return False

        self.owner_obj.irelatives.append((self.resolvedby.rebased_addr, self.addr))

class MipsGlobalReloc(GenericAbsoluteReloc):
    pass

class MipsLocalReloc(Relocation):
    def relocate(self, solist, bypass_compatibility=False): # pylint: disable=unused-argument
        if self.owner_obj.rebase_addr == 0:
            self.resolve(None)
            return True                     # don't touch local relocations on the main bin
        delta = self.owner_obj.rebase_addr - self.owner_obj._dynamic['DT_MIPS_BASE_ADDRESS']
        if delta == 0:
            self.resolve(None)
            return True
        elif delta < 0:
            raise CLEOperationError("We are relocating a MIPS object at a lower address than"
                                    " its static base address. This is weird.")
        val = self.owner_obj.memory.read_addr_at(self.addr)
        newval = val + delta
        self.owner_obj.memory.write_addr_at(self.addr, newval)
        self.resolve(None)
        return True
