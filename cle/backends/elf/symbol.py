from ..symbol import Symbol
from ...address_translator import AT

class ELFSymbol(Symbol):
    """
    Represents a symbol for the ELF format.

    :ivar str elftype:      The type of this symbol as an ELF enum string
    :ivar str binding:      The binding of this symbol as an ELF enum string
    :ivar section:          The section associated with this symbol, or None
    """
    def __init__(self, owner, symb):
        realtype = owner.arch.translate_symbol_type(symb.entry.st_info.type)
        if realtype == 'STT_FUNC':
            symtype = Symbol.TYPE_FUNCTION
        elif realtype == 'STT_OBJECT':
            symtype = Symbol.TYPE_OBJECT
        elif realtype == 'STT_SECTION':
            symtype = Symbol.TYPE_SECTION
        elif realtype == 'STT_NOTYPE':
            symtype = Symbol.TYPE_NONE
        else:
            symtype = Symbol.TYPE_OTHER

        sec_ndx, value = symb.entry.st_shndx, symb.entry.st_value

        # A relocatable object's symbol's value is relative to its section's addr.
        if owner.is_relocatable and isinstance(sec_ndx, (int, long)):
            value += owner.sections[sec_ndx].remap_offset

        super(ELFSymbol, self).__init__(owner,
                                        symb.name,
                                        AT.from_lva(value, owner).to_rva(),
                                        symb.entry.st_size,
                                        symtype)

        self.elftype = realtype
        self.binding = symb.entry.st_info.bind
        self.section = sec_ndx if type(sec_ndx) is not str else None
        self.is_static = self.type == Symbol.TYPE_SECTION or sec_ndx == 'SHN_ABS'
        self.is_common = sec_ndx == 'SHN_COMMON'
        self.is_weak = self.binding == 'STB_WEAK'

        # these do not appear to be 100% correct, but they work so far...
        # e.g. the "stdout" import symbol will be marked as an export symbol by this
        # there does not seem to be a good way to reliably isolate import symbols
        self.is_import = self.section is None and self.binding in ('STB_GLOBAL', 'STB_WEAK')
        self.is_export = self.section is not None and self.binding in ('STB_GLOBAL', 'STB_WEAK')
