from .. import Symbol

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
        self.is_foward = forwarder is not None

    def resolve_forwarder(self):
        sym = self
        while sym is not None and sym.is_foward and sym.forwarder is not None: # FORWARDING
            owner, name = sym.forwarder.split('.', 1)
            owner_obj = self.owner_obj.loader.find_object(owner)
            if owner_obj is None:
                return None
            sym = owner_obj.get_symbol(name)

        return sym
