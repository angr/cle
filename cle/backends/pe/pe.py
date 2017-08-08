import os
import struct
import logging
import archinfo
import pefile

from .symbol import WinSymbol
from .reloc import WinReloc
from .regions import PESection
from .. import register_backend, Backend
from ...address_translator import AT

l = logging.getLogger('cle.pe')


class PE(Backend):
    """
    Representation of a PE (i.e. Windows) binary.
    """

    def __init__(self, *args, **kwargs):
        super(PE, self).__init__(*args, **kwargs)
        self.segments = self.sections # in a PE, sections and segments have the same meaning
        self.os = 'windows'
        if self.binary is None:
            self._pe = pefile.PE(data=self.binary_stream.read())
        elif self.binary in self._pefile_cache: # these objects are not mutated, so they are reusable within a process
            self._pe = self._pefile_cache[self.binary]
        else:
            self._pe = pefile.PE(self.binary)
            self._pefile_cache[self.binary] = self._pe

        if self.arch is None:
            self.set_arch(archinfo.arch_from_id(pefile.MACHINE_TYPE[self._pe.FILE_HEADER.Machine]))

        self.mapped_base = self.linked_base = self._pe.OPTIONAL_HEADER.ImageBase
        self._entry = AT.from_rva(self._pe.OPTIONAL_HEADER.AddressOfEntryPoint, self).to_lva()

        if hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
            self.deps = [entry.dll.lower() for entry in self._pe.DIRECTORY_ENTRY_IMPORT]
        else:
            self.deps = []

        if self.binary is not None and not self.is_main_bin:
            self.provides = os.path.basename(self.binary).lower()
        else:
            self.provides = None

        self.tls_used = False
        self.tls_data_start = None
        self.tls_data_size = None
        self.tls_index_address = None
        self.tls_callbacks = None
        self.tls_size_of_zero_fill = None
        self.tls_module_id = None
        self.tls_data_pointer = None

        self._exports = {}
        self._ordinal_exports = {}
        self._symbol_cache = self._exports # same thing
        self._handle_imports()
        self._handle_exports()
        self._handle_relocs()
        self._register_tls()
        self._register_sections()
        self.linking = 'dynamic' if self.deps else 'static'

        self.jmprel = self._get_jmprel()

        self.memory.add_backer(0, self._pe.get_memory_mapped_image())

    _pefile_cache = {}

    @staticmethod
    def is_compatible(stream):
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith('MZ') and len(identstring) > 0x40:
            peptr = struct.unpack('I', identstring[0x3c:0x40])[0]
            if peptr < len(identstring) and identstring[peptr:peptr + 4] == 'PE\0\0':
                return True
        return False

    @classmethod
    def check_compatibility(cls, spec, obj):
        if hasattr(spec, 'read') and hasattr(spec, 'seek'):
            pe = pefile.PE(data=spec.read(), fast_load=True)
        else:
            pe = pefile.PE(spec, fast_load=True)

        arch = archinfo.arch_from_id(pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine])
        return arch == obj.arch

    #
    # Public methods
    #

    def get_symbol(self, name):
        if name.startswith('ordinal.'):
            return self._ordinal_exports.get(int(name.split('.')[1]), None)
        return self._exports.get(name, None)

    @property
    def supports_nx(self):
        return self._pe.OPTIONAL_HEADER.DllCharacteristics & 0x100 != 0

    #
    # Private methods
    #

    def _get_jmprel(self):
        return self.imports

    def _handle_imports(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    imp_name = imp.name
                    if imp_name is None: # must be an import by ordinal
                        imp_name = "%s.ordinal.%d" % (entry.dll, imp.ordinal)
                    symb = WinSymbol(self, imp_name, 0, True, False, imp.ordinal)
                    reloc = WinReloc(self, symb, AT.from_lva(imp.address, self).to_rva(), entry.dll)
                    self.imports[imp_name] = reloc
                    self.relocs.append(reloc)

    def _handle_exports(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_EXPORT'):
            symbols = self._pe.DIRECTORY_ENTRY_EXPORT.symbols
            for exp in symbols:
                symb = WinSymbol(self, exp.name, exp.address, False, True, exp.ordinal)
                self._exports[exp.name] = symb
                self._ordinal_exports[exp.ordinal] = symb

    def _handle_relocs(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_BASERELOC'):
            for base_reloc in self._pe.DIRECTORY_ENTRY_BASERELOC:
                entry_idx = 0
                while entry_idx < len(base_reloc.entries):
                    reloc_data = base_reloc.entries[entry_idx]
                    if reloc_data.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']: #occupies 2 entries
                        if entry_idx == len(base_reloc.entries):
                            l.warning('PE contains corrupt relocation table')
                            break
                        next_entry = base_reloc.entries[entry_idx]
                        entry_idx += 1
                        reloc = WinReloc(self, None, reloc_data.rva, None, reloc_type=reloc_data.type, next_rva=next_entry.rva)
                    else:
                        reloc = WinReloc(self, None, reloc_data.rva, None, reloc_type=reloc_data.type)
                    self.relocs.append(reloc)
                    entry_idx += 1

    def _register_tls(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_TLS'):
            tls = self._pe.DIRECTORY_ENTRY_TLS.struct

            self.tls_used = True
            self.tls_data_start = tls.StartAddressOfRawData
            self.tls_data_size = tls.EndAddressOfRawData - tls.StartAddressOfRawData
            self.tls_index_address = tls.AddressOfIndex
            self.tls_callbacks = self._register_tls_callbacks(tls.AddressOfCallBacks)
            self.tls_size_of_zero_fill = tls.SizeOfZeroFill

    def _register_tls_callbacks(self, addr):
        """
        TLS callbacks are stored as an array of virtual addresses to functions.
        The last entry is empty (NULL), which indicates the end of the table
        """
        callbacks = []

        callback_rva = AT.from_lva(addr, self).to_rva()
        callback = self._pe.get_dword_at_rva(callback_rva)
        while callback != 0:
            callbacks.append(callback)
            callback_rva += 4
            callback = self._pe.get_dword_at_rva(callback_rva)

        return callbacks

    def _register_sections(self):
        """
        Wrap self._pe.sections in PESection objects, and add them to self.sections.
        """

        for pe_section in self._pe.sections:
            section = PESection(pe_section, remap_offset=self.linked_base)
            self.sections.append(section)
            self.sections_map[section.name] = section

register_backend('pe', PE)
