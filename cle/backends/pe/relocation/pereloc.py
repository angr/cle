from __future__ import annotations

import logging

from cle.backends.relocation import Relocation

log = logging.getLogger(name=__name__)
unimplemented_log = set()


# Reference: https://msdn.microsoft.com/en-us/library/ms809762.aspx
class PEReloc(Relocation):
    __slots__ = ()

    AUTO_HANDLE_NONE = True

    def __init__(self, owner, symbol, addr, resolvewith=None):  # pylint: disable=unused-argument
        super().__init__(owner, symbol, addr)

        self.resolvewith = resolvewith
        if self.resolvewith is not None:
            self.resolvewith = self.resolvewith.lower()

    def resolve_symbol(self, solist, bypass_compatibility=False, extern_object=None, **kwargs):
        if not bypass_compatibility:
            solist = [x for x in solist if self.resolvewith == x.provides]
        super().resolve_symbol(solist, bypass_compatibility=bypass_compatibility, extern_object=extern_object, **kwargs)

        if self.resolvedby is None:
            return

        # handle symbol forwarders
        newsym = self.resolvedby.resolve_forwarder()
        if newsym is None:
            new_symbol = extern_object.make_extern(self.symbol.name, sym_type=self.symbol.type)
            self.resolvedby.resolvedby = new_symbol
            self.resolve(new_symbol)
            return

        self.resolvedby = newsym
        self.symbol.resolvedby = newsym

    def relocate(self):
        if self.symbol is None:  # relocation described in the DIRECTORY_ENTRY_BASERELOC table
            value = self.value
            if value is None:
                log.debug("%s at %#x was not applied", type(self).__name__, self.relative_addr)
                return
            self.owner.memory.store(self.relative_addr, value)
        else:
            super().relocate()

    @property
    def value(self):
        if self.symbol is None:
            # A base relocation rewrites the bytes at the fixup site, which only a subclass that
            # knows the encoding can do. Reaching here means the type is recognized but has no
            # implementation, so the fixup stays as the linker wrote it.
            name = type(self).__name__
            if name not in unimplemented_log:
                unimplemented_log.add(name)
                log.warning("%s is not implemented, so base relocations of this type are not applied", name)
            return None
        if self.resolved:
            return self.resolvedby.rebased_addr
        return None

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
