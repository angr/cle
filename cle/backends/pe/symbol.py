from .. import Symbol

class WinSymbol(Symbol):
    """
    Represents a symbol for the PE format.
    """
    def __init__(self, owner, name, addr, is_import, is_export, ordinal_number):
        super(WinSymbol, self).__init__(owner, name, addr, owner.arch.bytes, Symbol.TYPE_FUNCTION)
        self.is_import = is_import
        self.is_export = is_export
        self.ordinal_number = ordinal_number
