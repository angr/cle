import pefile
from .absobj import AbsObj

__all__ = ('Pe',)

class Pe(AbsObj):
    """
    Representation of a PE (i.e. Windows) binary
    """

    def __init__(self, *args, **kwargs):
        super(Pe, self).__init__(*args, **kwargs)

        self._pe = pefile.PE(self.binary)

        self._base = self._pe.OPTIONAL_HEADER.ImageBase
        self.entry = self._base + self._pe.OPTIONAL_HEADER.AddressOfEntryPoint

        self.imports = self._get_imports()
        self.exports = self._get_exports()
        self.deps = [entry.dll for entry in self._pe.DIRECTORY_ENTRY_IMPORT]
        self.linking = 'dynamic'
        self.resolved_imports = {}
        self.jmprel = self._get_jmprel()

        self.memory.add_backer(self._base, self._pe.get_memory_mapped_image())

    def get_min_addr(self):
        return min(self._base + section.VirtualAddress for section in self._pe.sections)

    def get_max_addr(self):
        return max(self._base + section.VirtualAddress + section.Misc_VirtualSize - 1
                   for section in self._pe.sections)

    def _get_jmprel(self):
        return self.imports

    def _get_imports(self):
        return {imp.name: imp.address for entry in self._pe.DIRECTORY_ENTRY_IMPORT for imp in entry.imports}

    def _get_exports(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_EXPORT'):
            symbols = self._pe.DIRECTORY_ENTRY_EXPORT.symbols
            return {exp.name: self._pe.OPTIONAL_HEADER.ImageBase + exp.address for exp in symbols}
        else:
            return {}
