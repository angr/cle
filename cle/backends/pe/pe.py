import os
import struct
import logging
import archinfo
import pefile
from .symbol import WinSymbol
from .regions import PESection
from .relocation.generic import DllImport, IMAGE_REL_BASED_HIGHADJ, IMAGE_REL_BASED_ABSOLUTE
from .relocation import get_relocation
from .. import register_backend, Backend
from ...address_translator import AT
from ...patched_stream import PatchedStream


l = logging.getLogger('cle.pe')


class PE(Backend):
    """
    Representation of a PE (i.e. Windows) binary.
    """
    is_default = True # Tell CLE to automatically consider using the PE backend

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
            if not self.is_main_bin:
                # only cache shared libraries, the main binary will not be reused
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

        self.supports_nx = self._pe.OPTIONAL_HEADER.DllCharacteristics & 0x100 != 0
        self.pic = self._pe.OPTIONAL_HEADER.DllCharacteristics & 0x40 != 0

        self._exports = {}
        self._ordinal_exports = {}
        self._symbol_cache = self._exports # same thing
        self._handle_imports()
        self._handle_exports()
        self.__register_relocs()
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
        """
        Look up the symbol with the given name. Symbols can be looked up by ordinal with the name ``"ordinal.%d" % num``
        """
        if name.startswith('ordinal.'):
            return self._ordinal_exports.get(int(name.split('.')[1]), None)
        return self._exports.get(name, None)

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
                        imp_name = "ordinal.%d.%s" % (imp.ordinal, entry.dll.lower())

                    symb = WinSymbol(owner=self, name=imp_name, addr=0, is_import=True, is_export=False, ordinal_number=imp.ordinal, forwarder=None)
                    reloc = self._make_reloc(addr=AT.from_lva(imp.address, self).to_rva(), reloc_type=None, symbol=symb, resolvewith=entry.dll)

                    if reloc is not None:
                        self.imports[imp_name] = reloc
                        self.relocs.append(reloc)


    def _handle_exports(self):
        if hasattr(self._pe, 'DIRECTORY_ENTRY_EXPORT'):
            symbols = self._pe.DIRECTORY_ENTRY_EXPORT.symbols
            for exp in symbols:
                symb = WinSymbol(self, exp.name, exp.address, False, True, exp.ordinal, exp.forwarder)
                self._exports[exp.name] = symb
                self._ordinal_exports[exp.ordinal] = symb


                if exp.forwarder is not None:
                    forwardlib = exp.forwarder.split('.', 1)[0].lower() + '.dll'
                    if forwardlib not in self.deps:
                        self.deps.append(forwardlib)


    def __register_relocs(self):
        if not hasattr(self._pe, 'DIRECTORY_ENTRY_BASERELOC'):
            l.debug("%s has no relocations", self.binary)
            return

        for base_reloc in self._pe.DIRECTORY_ENTRY_BASERELOC:
            entry_idx = 0
            while entry_idx < len(base_reloc.entries):
                reloc_data = base_reloc.entries[entry_idx]
                if reloc_data.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHADJ']: # special case, occupies 2 entries
                    if entry_idx == len(base_reloc.entries):
                        l.warning('PE contains corrupt base relocation table')
                        break

                    next_entry = base_reloc.entries[entry_idx]
                    entry_idx += 1
                    reloc = self._make_reloc(addr=reloc_data.rva, reloc_type=reloc_data.type, next_rva=next_entry.rva)
                else:
                    reloc = self._make_reloc(addr=reloc_data.rva, reloc_type=reloc_data.type)

                if reloc is not None:
                    self.pic = True # I've seen binaries with the DYNAMIC_BASE DllCharacteristic unset but have tons of fixup relocations
                    self.relocs.append(reloc)

                entry_idx += 1

        return self.relocs

    def _make_reloc(self, addr, reloc_type, symbol=None, next_rva=None, resolvewith=None):

        # Handle special cases first

        if reloc_type == 0:         # 0 simply means "ignore this relocation"
            reloc = IMAGE_REL_BASED_ABSOLUTE(owner=self, symbol=symbol, addr=addr, resolvewith=resolvewith)
            return reloc
        if reloc_type is None:      # for DLL imports
            reloc = DllImport(owner=self, symbol=symbol, addr=addr, resolvewith=resolvewith)
            return reloc
        if next_rva is not None:
            reloc = IMAGE_REL_BASED_HIGHADJ(owner=self, addr=addr, next_rva=next_rva)
            return reloc

        # Handle all the normal base relocations
        RelocClass = get_relocation(self.arch.name, reloc_type)
        if RelocClass is None:
            l.debug('Failed to find relocation class for arch %s, type %d', 'pe'+self.arch.name, reloc_type)
            return None

        cls = RelocClass(owner=self, symbol=symbol, addr=addr)
        if cls is None:
            l.warn('Failed to retrieve relocation for %s of type %s', symbol.name, reloc_type)

        return cls

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
        while callback != 0 and callback is not None:
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

    def __getstate__(self):
        if self.binary is None:
            raise ValueError("Can't pickle an object loaded from a stream")

        out = dict(self.__dict__)
        out['_pe'] = None

        if type(self.binary_stream) is PatchedStream:
            out['binary_stream'].stream = None
        else:
            out['binary_stream'] = None

        return out

    def _setstate__(self, out):
        self.__dict__.update(out)

        if self.binary_stream is None:
            self.binary_stream = open(self.binary, 'rb')
        else:
            self.binary_stream.stream = open(self.binary, 'rb')

        if self.binary in self._pefile_cache: # these objects are not mutated, so they are reusable within a process
            self._pe = self._pefile_cache[self.binary]
        else:
            self._pe = pefile.PE(self.binary)
            if not self.is_main_bin:
                # only cache shared libraries, the main binary will not be reused
                self._pefile_cache[self.binary] = self._pe


register_backend('pe', PE)
