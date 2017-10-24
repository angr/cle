import logging

from .. import Symbol

l = logging.getLogger('cle.backends.pe.symbol')

class WinSymbol(Symbol):
    """
    Represents a symbol for the PE format.
    """
    def __init__(self, owner, name, addr, is_import, is_export, ordinal_number, forwarder):
        super(WinSymbol, self).__init__(owner, name, addr, owner.arch.bytes, Symbol.TYPE_FUNCTION)
        self.is_import = is_import
        self.is_export = is_export
        self.ordinal_number = ordinal_number
        self.forwarder = forwarder
        self.is_forward = forwarder is not None

    def resolve_forwarder(self):
        if self.resolvedby is not None:
            return self.resolvedby

        sym = self
        seen = set()
        while sym is not None and sym.is_forward and sym.forwarder is not None: # FORWARDING
            if sym.forwarder in seen:
                l.warning("Infinite forwarding loop for %s", self)
                return None
            seen.add(sym.forwarder)
            owner, name = sym.forwarder.split('.', 1)
            owner_obj = self.owner_obj.loader.find_object(owner)
            if owner_obj is None:
                return None
            sym = owner_obj.get_symbol(name)

        self.resolvedby = sym
        return sym
