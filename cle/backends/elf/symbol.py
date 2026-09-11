from __future__ import annotations

from elftools.elf.constants import SHN_INDICES
from elftools.elf.enums import ENUM_ST_INFO_TYPE

from cle.address_translator import AT
from cle.backends.symbol import Symbol, SymbolType

from .symbol_type import ELFSymbolType, parse_symbol_type


def maybedecode(string):
    return string if isinstance(string, str) else string.decode()


class ELFSymbol(Symbol):
    """
    Represents a symbol for the ELF format.

    :ivar str binding:      The binding of this symbol as an ELF enum string
    :ivar section:          The section associated with this symbol, or None
    :ivar _subtype:         The ELFSymbolType of this symbol
    """

    def __init__(self, owner, symb):
        subtype_num = ENUM_ST_INFO_TYPE.get(symb.entry.st_info.type, symb.entry.st_info.type)
        if "UNIX" in owner.os:
            arches = (owner.arch.name, "gnu", None)
        else:
            arches = (owner.arch.name, None)
        self._subtype, self._type = parse_symbol_type(subtype_num, arches)

        sec_ndx, value = symb.entry.st_shndx, symb.entry.st_value

        # pyelftools decodes SHN_UNDEF, SHN_ABS and SHN_COMMON to strings and passes every other st_shndx
        # through as an int. Values from SHN_LORESERVE up are reserved tags, such as the processor-specific
        # SHN_X86_64_LCOMMON, and do not index the section header table.
        reserved_ndx = isinstance(sec_ndx, int) and sec_ndx >= SHN_INDICES.SHN_LORESERVE
        section = None if reserved_ndx or isinstance(sec_ndx, str) else sec_ndx

        # A relocatable object's symbol's value is relative to its section's addr.
        if owner.is_relocatable and section is not None:
            value += owner.sections[section].remap_offset

        super().__init__(
            owner, maybedecode(symb.name), AT.from_lva(value, owner).to_rva(), symb.entry.st_size, self.type
        )

        self.version = None
        self.binding = symb.entry.st_info.bind
        self.is_hidden = symb.entry["st_other"]["visibility"] == "STV_HIDDEN"
        self.section = section
        self.is_static = self._type == SymbolType.TYPE_SECTION or sec_ndx == "SHN_ABS"
        self.is_common = sec_ndx == "SHN_COMMON"
        self.is_weak = self.binding == "STB_WEAK"
        self.is_local = self.binding == "STB_LOCAL"

        self.is_import = sec_ndx == "SHN_UNDEF" and self.binding in ("STB_GLOBAL", "STB_WEAK")
        # A reserved st_shndx names no section, but the symbol is still defined here, the way a SHN_COMMON
        # one is: SHN_X86_64_LCOMMON is what a large common symbol gets instead of SHN_COMMON.
        defined_here = self.section is not None or self.is_common or reserved_ndx
        self.is_export = defined_here and self.binding in ("STB_GLOBAL", "STB_WEAK")

    @property
    def subtype(self) -> ELFSymbolType:
        return self._subtype
