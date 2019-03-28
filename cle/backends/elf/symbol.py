from enum import Enum
from ..symbol import Symbol, SymbolType, SymbolSubType
from ...address_translator import AT

def maybedecode(string):
    return string if type(string) is str else string.decode()


class ElfSymbolType(SymbolSubType):
    """
    ELF-specific symbol types
    """
    STT_NOTYPE = 0     # Symbol's type is not specified
    STT_OBJECT = 1     # Symbol is a data object (variable, array, etc.)
    STT_FUNC = 2       # Symbol is executable code (function, etc.)
    STT_SECTION = 3    # Symbol refers to a section
    STT_FILE = 4       # Local, absolute symbol that refers to a file
    STT_COMMON = 5     # An uninitialized common block
    STT_TLS = 6        # Thread local data object

    STT_GNU_IFUNC = 10 # GNU indirect function
    STT_LOOS = 10      # Lowest operating system-specific symbol type
    STT_HIOS = 12      # Highest operating system-specific symbol type
    STT_LOPROC = 13    # Lowest processor-specific symbol type
    STT_HIPROC = 15    # Highest processor-specific symbol type

    # AMDGPU symbol types
    STT_AMDGPU_HSA_KERNEL = 10

    def to_base_type(self):
        if self is ElfSymbolType.STT_NOTYPE:
            return SymbolType.TYPE_NONE
        elif self is ElfSymbolType.STT_FUNC:
            return SymbolType.TYPE_FUNCTION
        elif self in [ElfSymbolType.STT_OBJECT, ElfSymbolType.STT_COMMON]:
            return SymbolType.TYPE_OBJECT
        elif self is ElfSymbolType.STT_SECTION:
            return SymbolType.TYPE_SECTION
        elif self is ElfSymbolType.STT_TLS:
            return SymbolType.TYPE_TLS_OBJECT
        # TODO: Fill in the rest of these
        else:
            return SymbolType.TYPE_OTHER


class ELFSymbol(Symbol):
    """
    Represents a symbol for the ELF format.

    :ivar str binding:      The binding of this symbol as an ELF enum string
    :ivar section:          The section associated with this symbol, or None
    :ivar _subtype:         The ElfSymbolType of this symbol
    """
    def __init__(self, owner, symb):
        self._subtype = ElfSymbolType[symb.entry.st_info.type]

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
    def type(self):
        return self._subtype.to_base_type()

    @property
    def subtype(self):
        return self._subtype
