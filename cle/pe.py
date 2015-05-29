import pefile
import archinfo
import os
from .absobj import AbsObj, Symbol, Relocation

__all__ = ('PE',)

import logging
l = logging.getLogger('cle.pe')

class WinSymbol(Symbol):
    def __init__(self, owner, name, addr, is_import, is_export):
        super(WinSymbol, self).__init__(owner, name, addr, owner.arch.bytes, None, None, None)
        self._is_import = is_import
        self._is_export = is_export

    @property
    def is_import(self):
        return self._is_import

    @property
    def is_export(self):
        return self._is_export

class WinReloc(Relocation):
    def __init__(self, owner, symbol, addr, resolvewith):
        super(WinReloc, self).__init__(owner, symbol, addr, None, None)
        self.resolvewith = resolvewith

    def relocate(self, solist):
        return self.reloc_global([x for x in solist if self.resolvewith == x.soname])

class PE(AbsObj):
    """
    Representation of a PE (i.e. Windows) binary
    """

    def __init__(self, *args, **kwargs):
        super(PE, self).__init__(*args, **kwargs)

        self._pe = pefile.PE(self.binary)

        if self.arch is None:
            self.set_arch(archinfo.arch_from_id(pefile.MACHINE_TYPE[self._pe.FILE_HEADER.Machine]))

        self.requested_base = self._pe.OPTIONAL_HEADER.ImageBase
        self._entry = self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

        if hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
            self.deps = [entry.dll for entry in self._pe.DIRECTORY_ENTRY_IMPORT]
        else:
            self.deps = []

        self.soname = os.path.basename(self.binary)
        if not self.soname.endswith('.dll'):
            self.soname = None

        self._exports = {}
        self._handle_imports()
        self._handle_exports()
        self.linking = 'dynamic' if len(self.deps) > 0 else 'static'

        self.jmprel = self._get_jmprel()

        self.memory.add_backer(0, self._pe.get_memory_mapped_image())

        l.warning('The PE module is not well, supported. Good luck!')

    supported_filetypes = ['pe']

    def get_min_addr(self):
        return min(section.VirtualAddress - self.requested_base + self.rebase_addr for section in self._pe.sections)

    def get_max_addr(self):
        return max(section.VirtualAddress - self.requested_base + self.rebase_addr + section.Misc_VirtualSize - 1
                   for section in self._pe.sections)

    def get_symbol(self, name):
        return self._exports.get(name, None)

    def _get_jmprel(self):
        return self.imports

    def _handle_imports(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    symb = WinSymbol(self, imp.name, 0, True, False)
                    reloc = WinReloc(self, symb, imp.address - self.requested_base, entry.dll)
                    self.imports[imp.name] = reloc
                    self.relocs.append(reloc)

    def _handle_exports(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_EXPORT'):
            symbols = self._pe.DIRECTORY_ENTRY_EXPORT.symbols
            for exp in symbols:
                symb = WinSymbol(self, exp.name, exp.address - self.requested_base, False, True)
                self._exports[exp.name] = symb
