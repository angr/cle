import logging
from ...relocation import Relocation

l=logging.getLogger('cle.cle.backends.pe.relocation.pereloc')

# Reference: https://msdn.microsoft.com/en-us/library/ms809762.aspx
class PEReloc(Relocation):
    def __init__(self, owner, symbol, addr, resolvewith=None):   # pylint: disable=unused-argument
        super(PEReloc, self).__init__(owner, symbol, addr)

        self.resolvewith = resolvewith
        if self.resolvewith is not None:
            self.resolvewith = self.resolvewith.lower()

    def resolve_symbol(self, solist, bypass_compatibility=False, thumb=False):
        if not bypass_compatibility:
            solist = [x for x in solist if self.resolvewith == x.provides]
        out = super(PEReloc, self).resolve_symbol(solist)

        if not out:
            return False

        newsym = self.resolvedby.resolve_forwarder()
        if newsym is None:
            new_symbol = self.owner.loader.extern_object.make_extern(self.symbol.name, sym_type=self.symbol.type)
            self.resolvedby.resolvedby = new_symbol
            self.resolve(new_symbol)
            return True

        self.resolvedby = newsym
        self.symbol.resolvedby = newsym
        return True

    def relocate(self, solist, bypass_compatibility=False):
        if self.symbol is None:  # relocation described in the DIRECTORY_ENTRY_BASERELOC table
            if self.value is None:
                l.debug('Unresolved relocation with no symbol.')
                return
            self.owner.memory.store(self.relative_addr, self.value)
        else:
            return super(PEReloc, self).relocate(solist, bypass_compatibility)

    @property
    def value(self):
        if self.resolved:
            return self.resolvedby.rebased_addr

    @property
    def is_base_reloc(self):
        """
        These relocations are ignored by the linker if the executable
        is loaded at its preferred base address. There is no associated
        symbol with base relocations.
        """
        return True if self.symbol is None else False

    @property
    def is_import(self):
        return not self.is_base_reloc
