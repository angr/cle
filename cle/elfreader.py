import readelf
from itertools import chain
from .abs_obj import AbsObj

class Elf(AbsObj):
    def __init__(self, binary, **kwargs):
        super(Elf, self).__init__(binary, **kwargs)
        self.reader = readelf.ELFFile(open(self.binary))
        self._symbols = []
        self.symbols = {}

        self._symb_sections = []
        self._strtab_sections = []
        self._reloc_sections = []

        self.elfflags = self.reader.header.e_flags
        self.archinfo.elfflags = self.elfflags

        self.__register_segments()
        self.__register_sections()
        self.__register_symbols()

    def __register_segments(self):
        for seg_readelf in self.reader.iter_segments():
            pass # what do I need to do here

    def __register_sections(self):
        for sec_readelf in self.reader.iter_sections():
            if isinstance(sec_readelf, readelf.SymbolTableSection):
                self._symb_sections.append(sec_readelf)
            elif isinstance(sec_readelf, readelf.StringTableSection):
                self._strtab_sections.append(sec_readelf)
            elif isinstance(sec_readelf, readelf,RelocationSection):
                self._reloc_sections.append(sec_readelf)

    def __register_symbols(self):
        for symb in chain(x.iter_symbols() for x in self._symb_sections):
            symbol = ElfSymbol(symb.name, symb.entry.st_value, symb.entry.st_size,
                               symb.entry.st_info.bind, symb.entry.st_info.type,
                               symb.entry.st_shndx if symb.entry.st_shndx != 'SHN_UNDEF' else None
                               )
            self._symbols.append(symbol)
            self._symbols[symbol.name] = symbol
