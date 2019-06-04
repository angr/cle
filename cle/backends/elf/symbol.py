from ..symbol import Symbol, SymbolType
from ...address_translator import AT
from .symbol_type import ELFSymbolType


def maybedecode(string):
    return string if type(string) is str else string.decode()


class ELFSymbol(Symbol):
    """
    Represents a symbol for the ELF format.

    :ivar str binding:      The binding of this symbol as an ELF enum string
    :ivar section:          The section associated with this symbol, or None
    :ivar _subtype:         The ELFSymbolType of this symbol
    """
    def __init__(self, owner, symb):
        self._subtype = ELFSymbolType[symb.entry.st_info.type]
        self._type = self._subtype.to_base_type()

        sec_ndx, value = symb.entry.st_shndx, symb.entry.st_value

        # A relocatable object's symbol's value is relative to its section's addr.
        if owner.is_relocatable and isinstance(sec_ndx, int):
            value += owner.sections[sec_ndx].remap_offset

        super(ELFSymbol, self).__init__(owner,
                                        maybedecode(symb.name),
                                        AT.from_lva(value, owner).to_rva(),
                                        symb.entry.st_size,
                                        self.type)

        self.binding = symb.entry.st_info.bind
        self.is_hidden = symb.entry['st_other']['visibility'] == 'STV_HIDDEN'
        self.section = sec_ndx if type(sec_ndx) is not str else None
        self.is_static = self._type == SymbolType.TYPE_SECTION or sec_ndx == 'SHN_ABS'
        self.is_common = sec_ndx == 'SHN_COMMON'
        self.is_weak = self.binding == 'STB_WEAK'
        self.is_local = self.binding == 'STB_LOCAL'

        # these do not appear to be 100% correct, but they work so far...
        # e.g. the "stdout" import symbol will be marked as an export symbol by this
        # there does not seem to be a good way to reliably isolate import symbols
        self.is_import = sec_ndx == 'SHN_UNDEF' and self.binding in ('STB_GLOBAL', 'STB_WEAK')
        self.is_export = self.section is not None and self.binding in ('STB_GLOBAL', 'STB_WEAK')

    @property
    def subtype(self) -> ELFSymbolType:
        return self._subtype
