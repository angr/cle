from . import Relocation

import logging
l = logging.getLogger('cle.relocations.generic_elf')

class GenericTLSModIdReloc(Relocation):
    def relocate(self, solist, bypass_compatibility=False):
        if self.symbol.type == 'STT_NOTYPE':
            self.owner_obj.memory.write_addr_at(self.addr, self.owner_obj.tls_module_id)
            self.resolve(None)
        else:
            if not self.resolve_symbol(solist):
                return False
            self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.owner_obj.tls_module_id)
        return True

class GenericTLSDoffsetReloc(Relocation):
    @property
    def value(self):
        return self.addend + self.symbol.addr

    def resolve_symbol(self, solist, bypass_compatibility=False):   # pylint: disable=unused-argument
        self.resolve(None)
        return True

class GenericTLSOffsetReloc(Relocation):
    def relocate(self, solist, bypass_compatibility=False):
        hell_offset = self.owner_obj.arch.elf_tls.tp_offset
        if self.symbol.type == 'STT_NOTYPE':
            self.owner_obj.memory.write_addr_at(self.addr, self.owner_obj.tls_block_offset + self.addend + self.symbol.addr - hell_offset)
            self.resolve(None)
        else:
            if not self.resolve_symbol(solist, bypass_compatibility):
                return False
            self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.owner_obj.tls_block_offset + self.addend + self.symbol.addr - hell_offset)
        return True
