from __future__ import annotations

import itertools
import logging
import os
import re
import struct
from collections.abc import Callable

import archinfo
import pefile
import pyxdia

from cle.address_translator import AT
from cle.backends.backend import Backend, FunctionHint, FunctionHintSource, register_backend
from cle.backends.symbol import SymbolType
from cle.structs import DataDirectory, MemRegion, MemRegionSort, PointerArray, StringBlob, StructArray
from cle.utils import extract_null_terminated_bytestr

from .regions import PESection
from .relocation import get_relocation
from .relocation.generic import IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_HIGHADJ, DllImport
from .symbol import WinSymbol
from .symbolserver import PDBInfo, SymbolResolver

SECTION_NAME_STRING_TABLE_OFFSET_RE = re.compile(r"\/(\d+)")
VALID_SYMBOL_NAME_RE = re.compile(r"[A-Za-z0-9_@$?]+")

log = logging.getLogger(name=__name__)


class PE(Backend):
    """
    Representation of a PE (i.e. Windows) binary.

    Useful backend options:

    - ``debug_symbols``: Provides the path to a PDB file which contains the binary's debug symbols
    - ``debug_symbol_dirs``: List of directories to search for PDB files (searched before symbol servers)
    - ``debug_symbol_path_str``: A string indicating symbol search paths, which may be provided in the
                                _NT_SYMBOL_PATH format.
    - ``download_debug_symbols``: Whether to attempt downloading debug symbols from symbol servers (if provided) or
                                  not. Default to False.
    - ``download_debug_symbol_confirm``: A callable that takes a URL string and returns True if downloading the debug
                                         symbol from the URL is allowed by the user, False otherwise.
    - ``download_debug_symbol_progress``: A callable that takes two integer arguments: bytes downloaded and total bytes.
                                          This callable is called periodically to report download progress.
    - ``search_microsoft_symserver``: Whether to include the Microsoft symbol server in symbol searches. Default to
                                      True. Requires ``download_debug_symbols`` to be True to have any effect.
    """

    is_default = True  # Tell CLE to automatically consider using the PE backend

    def __init__(
        self,
        *args,
        debug_symbols=None,
        debug_symbol_dirs=None,
        debug_symbol_path_str: str | None = None,
        download_debug_symbols: bool = False,
        download_debug_symbol_confirm: Callable[[str], bool] | None = None,
        download_debug_symbol_progress: Callable[[int, int | None], bool] | None = None,
        search_microsoft_symserver: bool = True,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.set_load_args(debug_symbols=debug_symbols, debug_symbol_paths=debug_symbol_dirs)
        self._debug_symbol_dirs = debug_symbol_dirs or []
        self._debug_symbol_path_str = debug_symbol_path_str
        self._download_debug_symbols = download_debug_symbols
        self._download_debug_symbol_confirm = download_debug_symbol_confirm
        self._download_debug_symbol_progress = download_debug_symbol_progress
        self._search_microsoft_symserver = search_microsoft_symserver

        self.segments = self.sections  # in a PE, sections and segments have the same meaning
        self.os = "windows"
        self._raw_data = self._binary_stream.read()
        if self.binary is None:
            self._pe = pefile.PE(data=self._raw_data, fast_load=True)
            self._parse_pe_non_reloc_data_directories()
        elif self.binary in self._pefile_cache:  # these objects are not mutated, so they are reusable within a process
            self._pe = self._pefile_cache[self.binary]
        else:
            self._pe = pefile.PE(self.binary, fast_load=True)
            self._parse_pe_non_reloc_data_directories()
            if not self.is_main_bin:
                # only cache shared libraries, the main binary will not be reused
                self._pefile_cache[self.binary] = self._pe

        assert self._pe.FILE_HEADER is not None
        assert self._pe.OPTIONAL_HEADER is not None

        if self._arch is None:
            machine_type = self._pe.FILE_HEADER.Machine
            self.set_arch(archinfo.arch_from_id(pefile.MACHINE_TYPE.get(machine_type, hex(machine_type))))

        self.mapped_base = self.linked_base = self._pe.OPTIONAL_HEADER.ImageBase

        self._entry = AT.from_rva(self._pe.OPTIONAL_HEADER.AddressOfEntryPoint, self).to_lva()

        if hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            self.deps = [entry.dll.decode().lower() for entry in self._pe.DIRECTORY_ENTRY_IMPORT]
        else:
            self.deps = []

        if self.binary is not None and not self.is_main_bin:
            self.provides = os.path.basename(self.binary).lower()
        else:
            self.provides = None

        self.tls_index_address = None
        self.tls_callbacks = None

        self.supports_nx = self._pe.OPTIONAL_HEADER.DllCharacteristics & 0x100 != 0
        self.pic = self.pic or self._pe.OPTIONAL_HEADER.DllCharacteristics & 0x40 != 0
        if hasattr(self._pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            self.load_config = {
                name: value["Value"]
                for name, value in self._pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump_dict().items()
                if name != "Structure"
            }
        else:
            self.load_config = {}

        self._exports = {}
        self._ordinal_exports = {}
        self._symbol_cache = self._exports  # same thing
        self._handle_imports()
        self._handle_exports()
        self._handle_seh()
        self._parse_meta_regions()
        if self.loader._perform_relocations:
            # parse base relocs
            self._pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]])
            self.__register_relocs()
        # parse TLS
        self._register_tls()
        # parse sections
        self._register_sections()

        self.linking = "dynamic" if self.deps else "static"
        self.jmprel = self._get_jmprel()
        mapped_image = self._get_memory_mapped_image()
        if self.max_addr - self.min_addr < len(mapped_image):
            # we are loading more bytes than max_addr would allow (there is data at the end of the file that is not
            # covered by any sections), so we need to truncate mapped_image.
            # this is actually caused by PE.get_memory_mapped_image() not passing ignore_padding=True to
            # section.get_data().
            mapped_image = mapped_image[: self.max_addr - self.min_addr]
        self.memory.add_backer(0, mapped_image)

        if debug_symbols or self.loader._load_debug_info:
            pdb_path = debug_symbols or self._find_pdb_path()
            if pdb_path:
                self.load_symbols_from_pdb(pdb_path)

        self._load_symbols_from_coff_header()

        self.is_dotnet = (
            self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            ].VirtualAddress
            != 0
        )

    _pefile_cache = {}

    @classmethod
    def is_compatible(cls, stream):
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith(b"MZ") and len(identstring) > 0x40:
            peptr = struct.unpack("I", identstring[0x3C:0x40])[0]
            if peptr < len(identstring) and identstring[peptr : peptr + 4] == b"PE\0\0":
                return True
        return False

    @classmethod
    def check_magic_compatibility(cls, stream):
        stream.seek(0)
        identstring = stream.read(0x10)
        stream.seek(0)
        return identstring.startswith(b"MZ")

    @classmethod
    def check_compatibility(cls, spec, obj):
        if hasattr(spec, "read") and hasattr(spec, "seek"):
            pe = pefile.PE(data=spec.read(), fast_load=True)
        else:
            pe = pefile.PE(spec, fast_load=True)

        assert pe.FILE_HEADER is not None

        arch = archinfo.arch_from_id(pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine])
        return arch == obj.arch

    #
    # Public methods
    #

    def close(self):
        super().close()
        del self._pe
        del self._raw_data

    def get_symbol(self, name):
        """
        Look up the symbol with the given name. Symbols can be looked up by ordinal with the name ``"ordinal.%d" % num``
        """
        if name.startswith("ordinal."):
            return self._ordinal_exports.get(int(name.split(".")[1]), None)
        return super().get_symbol(name)

    def load_symbols_from_pdb(self, pdb_path):
        """
        Load available symbols from PDB at `pdb_path`
        """
        log.debug("Loading symbols from %s", pdb_path)
        try:
            pdb = pyxdia.PDB(pdb_path)
        except:  # noqa:E722 pylint:disable=bare-except
            log.exception("Failed to load PDB at %s", pdb_path)
            return

        if pdb.globals is None:  # pdbs may not have global symbols
            iterator = pdb.publics
        else:
            iterator = itertools.chain(pdb.globals, pdb.publics)

        for item in iterator:
            rva = item["relativeVirtualAddress"]
            if rva is None:
                continue
            name = item["name"]
            tag = str(item["symTag"])
            if tag == "PublicSymbol":
                # Marshall publics to data or function
                tag = "Function" if item.get("is_function", False) else "Data"
            symbol_type = {
                "Data": SymbolType.TYPE_OBJECT,
                "Function": SymbolType.TYPE_FUNCTION,
            }.get(tag, SymbolType.TYPE_OTHER)
            symb = WinSymbol(self, name, rva, False, False, None, None, symbol_type)
            log.debug("Adding symbol %s", str(symb))
            self.symbols.add(symb)

    #
    # Private methods
    #

    def _get_memory_mapped_image(self, max_virtual_address=0x100000000) -> bytes:
        """
        Get the data corresponding to the memory layout of the PE file as a single bytes object.

        This method replicates the feature of pefile.PE.get_memory_mapped_image() but with the addition of some logic
        for keeping partially mapped sections.
        """

        data = self._pe.__data__

        mapped_data_lst: list[bytes] = [self._pe.header]
        mapped_data_len = len(self._pe.header)
        for sec in self._pe.sections:
            if sec.Misc_VirtualSize == 0 and sec.SizeOfRawData == 0:
                # skip empty sections
                continue

            size = sec.SizeOfRawData
            ptr = self._pe.adjust_PointerToRawData(sec.PointerToRawData)
            va_adj = self._pe.adjust_SectionAlignment(
                sec.VirtualAddress,
                self._pe.OPTIONAL_HEADER.SectionAlignment,
                self._pe.OPTIONAL_HEADER.FileAlignment,
            )

            if ptr < len(data) < ptr + size:
                # truncated section, keep the part that is still within the file
                size = len(data) - ptr

            if ptr >= len(data) or ptr + size > len(data) or va_adj >= max_virtual_address:
                log.warning(
                    "Section %s has PointerToRawData %#x and SizeOfRawData %#x, which is out of bounds for the file "
                    "size. Skipping this section.",
                    sec.Name,
                    sec.PointerToRawData,
                    sec.SizeOfRawData,
                )
                continue

            padding_len = va_adj - mapped_data_len

            if padding_len > 0:
                mapped_data_lst.append(b"\x00" * padding_len)
            elif padding_len < 0:
                mapped_data = b"".join(mapped_data_lst)
                mapped_data_lst = [mapped_data[:padding_len]]
            mapped_data_len += padding_len

            sec_data = sec.get_data()
            mapped_data_lst.append(sec_data)
            mapped_data_len += len(sec_data)

        return b"".join(mapped_data_lst)

    def _parse_pe_non_reloc_data_directories(self):
        """
        Parse data directories that is not DIRECTORY_ENTRY_BASERELOC since parsing relocations can take a long time in
        many PE binaries.
        """

        directory_names = (
            "IMAGE_DIRECTORY_ENTRY_EXPORT",
            "IMAGE_DIRECTORY_ENTRY_IMPORT",
            "IMAGE_DIRECTORY_ENTRY_RESOURCE",
            "IMAGE_DIRECTORY_ENTRY_EXCEPTION",
            "IMAGE_DIRECTORY_ENTRY_SECURITY",
            "IMAGE_DIRECTORY_ENTRY_DEBUG",
            "IMAGE_DIRECTORY_ENTRY_COPYRIGHT",
            "IMAGE_DIRECTORY_ENTRY_GLOBALPTR",
            "IMAGE_DIRECTORY_ENTRY_TLS",
            "IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG",
            "IMAGE_DIRECTORY_ENTRY_IAT",
            "IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT",
            "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR",
            "IMAGE_DIRECTORY_ENTRY_RESERVED",
        )
        directories = [pefile.DIRECTORY_ENTRY[n] for n in directory_names]
        self._pe.parse_data_directories(directories=directories)

    def _get_jmprel(self):
        return self.imports

    def _handle_imports(self):
        if hasattr(self._pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self._pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is None:  # must be an import by ordinal
                        imp_name = f"ordinal.{imp.ordinal}.{entry.dll.lower().decode()}"
                    else:
                        imp_name = imp.name.decode()

                    symb = WinSymbol(
                        owner=self,
                        name=imp_name,
                        addr=0,
                        is_import=True,
                        is_export=False,
                        ordinal_number=imp.ordinal,
                        forwarder=None,
                    )
                    self.symbols.add(symb)
                    reloc = self._make_reloc(
                        addr=AT.from_lva(imp.address, self).to_rva(),
                        reloc_type=None,
                        symbol=symb,
                        resolvewith=entry.dll.decode(),
                    )

                    if reloc is not None:
                        self.imports[imp_name] = reloc
                        self.relocs.append(reloc)

    def _handle_exports(self):
        if hasattr(self._pe, "DIRECTORY_ENTRY_EXPORT"):
            symbols = self._pe.DIRECTORY_ENTRY_EXPORT.symbols
            for exp in symbols:
                name = exp.name.decode() if exp.name is not None else None
                forwarder = exp.forwarder.decode() if exp.forwarder is not None else None
                symb = WinSymbol(self, name, exp.address, False, True, exp.ordinal, forwarder)
                self.symbols.add(symb)
                self._exports[name] = symb
                self._ordinal_exports[exp.ordinal] = symb

                if forwarder is not None:
                    forwardlib = forwarder.split(".", 1)[0].lower() + ".dll"
                    if forwardlib not in self.deps:
                        self.deps.append(forwardlib)

    def _handle_seh(self):
        if hasattr(self._pe, "DIRECTORY_ENTRY_EXCEPTION"):
            for entry in self._pe.DIRECTORY_ENTRY_EXCEPTION:
                self.function_hints.append(
                    FunctionHint(
                        entry.struct.BeginAddress + self.linked_base,
                        entry.struct.EndAddress - entry.struct.BeginAddress,
                        FunctionHintSource.EH_FRAME,
                    )
                )

    def _parse_meta_regions(self):
        """
        Walk pefile's parsed data directories and build meta_regions describing the locations and layouts of PE
        metadata structures.
        All addresses are stored as linked virtual addresses (linked_base + RVA).
        """
        self._meta_iat()
        self._meta_exports()
        self._meta_imports()
        self._meta_delay_imports()
        self._meta_resources()
        self._meta_exceptions()
        self._meta_base_relocations()
        self._meta_debug()
        self._meta_tls()
        self._meta_load_config()
        self._meta_bound_imports()
        self._meta_com_descriptor()

    def _meta_pe_context(self) -> tuple[pefile.PE, int, bool, int]:
        """Return common values used by meta-region helpers: (pe, base, is_64, ptr_size)."""
        pe = self._pe
        base = self.linked_base
        is_64 = self.arch.bits == 64 if self._arch is not None else (pe.OPTIONAL_HEADER.Magic == 0x20B)
        ptr_size = 8 if is_64 else 4
        return pe, base, is_64, ptr_size

    def _meta_dd(self, name: str) -> pefile.Structure | None:
        """Return a data directory entry if it has a nonzero VirtualAddress and Size, else None."""
        idx = pefile.DIRECTORY_ENTRY[name]
        dd = self._pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
        if dd.VirtualAddress and dd.Size:
            return dd
        return None

    def _meta_iat(self):
        """IAT (Data Directory 12)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        iat_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_IAT")
        if iat_dd is None:
            return
        self.meta_regions.append(
            PointerArray(
                vaddr=base + iat_dd.VirtualAddress,
                entry_size=ptr_size,
                count=iat_dd.Size // ptr_size,
                sort=MemRegionSort.IAT,
            )
        )

    def _meta_exports(self):
        """Export Directory (Data Directory 0)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return
        exp_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_EXPORT")
        if exp_dd is None:
            return
        exp = pe.DIRECTORY_ENTRY_EXPORT
        exp_struct = exp.struct

        sub_regions: list[MemRegion] = []

        # Export directory header (IMAGE_EXPORT_DIRECTORY, 40 bytes)
        sub_regions.append(
            MemRegion(
                vaddr=base + exp_dd.VirtualAddress,
                size=exp_struct.sizeof(),
                sort=MemRegionSort.EXPORT_DIRECTORY,
            )
        )

        n_funcs = exp_struct.NumberOfFunctions
        n_names = exp_struct.NumberOfNames

        # AddressOfFunctions array
        if exp_struct.AddressOfFunctions and n_funcs:
            sub_regions.append(
                PointerArray(
                    vaddr=base + exp_struct.AddressOfFunctions,
                    entry_size=4,
                    count=n_funcs,
                    sort=MemRegionSort.EXPORT_ADDR_TABLE,
                )
            )

        # AddressOfNames array
        if exp_struct.AddressOfNames and n_names:
            sub_regions.append(
                PointerArray(
                    vaddr=base + exp_struct.AddressOfNames,
                    entry_size=4,
                    count=n_names,
                    sort=MemRegionSort.EXPORT_NAME_TABLE,
                )
            )

        # AddressOfNameOrdinals array
        if exp_struct.AddressOfNameOrdinals and n_names:
            sub_regions.append(
                PointerArray(
                    vaddr=base + exp_struct.AddressOfNameOrdinals,
                    entry_size=2,
                    count=n_names,
                    sort=MemRegionSort.EXPORT_ORDINAL_TABLE,
                )
            )

        # Export name strings: from end of ordinals table to end of export data directory
        if n_names and exp_struct.AddressOfNameOrdinals:
            strings_start = exp_struct.AddressOfNameOrdinals + n_names * 2
            strings_end = exp_dd.VirtualAddress + exp_dd.Size
            if strings_end > strings_start:
                sub_regions.append(
                    StringBlob(
                        vaddr=base + strings_start,
                        size=strings_end - strings_start,
                        sort=MemRegionSort.STRING_BLOB,
                    )
                )

        self.meta_regions.append(
            DataDirectory(
                vaddr=base + exp_dd.VirtualAddress,
                size=exp_dd.Size,
                sort=MemRegionSort.EXPORT_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

        # Extract function hints from exports
        exp_rva_start = exp_dd.VirtualAddress
        exp_rva_end = exp_dd.VirtualAddress + exp_dd.Size
        for sym in exp.symbols:
            if sym.forwarder is not None:
                continue
            # Forwarder RVAs point within the export directory; skip them
            if exp_rva_start <= sym.address < exp_rva_end:
                continue
            name = sym.name.decode() if sym.name else None
            self.function_hints.append(
                FunctionHint(
                    base + sym.address,
                    0,
                    FunctionHintSource.EXPORT_TABLE,
                    name=name,
                )
            )

    def _meta_imports(self):
        """Import Directory (Data Directory 1)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return
        imp_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_IMPORT")
        if imp_dd is None:
            return
        entries = pe.DIRECTORY_ENTRY_IMPORT

        sub_regions: list[MemRegion] = []

        # Import descriptor array (including null terminator)
        n_descs = len(entries) + 1  # +1 for null terminator
        sub_regions.append(
            StructArray(
                vaddr=base + imp_dd.VirtualAddress,
                entry_size=20,  # sizeof(IMAGE_IMPORT_DESCRIPTOR)
                count=n_descs,
                sort=MemRegionSort.IMPORT_DIRECTORY,
            )
        )

        # Per-DLL ILT arrays and track hint/name range
        hn_min = None
        hn_max = None
        for entry in entries:
            ilt_rva = entry.struct.OriginalFirstThunk
            if ilt_rva:
                n_imports = len(entry.imports) + 1  # +1 for null terminator
                sub_regions.append(
                    PointerArray(
                        vaddr=base + ilt_rva,
                        entry_size=ptr_size,
                        count=n_imports,
                        sort=MemRegionSort.ILT,
                    )
                )

            # Track hint/name table extent
            for imp in entry.imports:
                if imp.hint_name_table_rva:
                    rva = imp.hint_name_table_rva
                    # Each hint/name entry = 2 byte hint + name + null byte, word-aligned
                    name_len = len(imp.name) + 1 if imp.name else 1
                    entry_size = 2 + name_len
                    if entry_size % 2:
                        entry_size += 1
                    entry_end = rva + entry_size
                    if hn_min is None or rva < hn_min:
                        hn_min = rva
                    if hn_max is None or entry_end > hn_max:
                        hn_max = entry_end

        # Hint/Name table blob
        if hn_min is not None and hn_max is not None:
            sub_regions.append(
                StringBlob(
                    vaddr=base + hn_min,
                    size=hn_max - hn_min,
                    sort=MemRegionSort.IMPORT_HINT_NAME_TABLE,
                )
            )

        # DLL name strings (pointed to by each descriptor's Name field)
        for entry in entries:
            name_rva = entry.struct.Name
            if name_rva and entry.dll:
                sub_regions.append(
                    StringBlob(
                        vaddr=base + name_rva,
                        size=len(entry.dll) + 1,  # +1 for null terminator
                        sort=MemRegionSort.STRING_BLOB,
                    )
                )

        self.meta_regions.append(
            DataDirectory(
                vaddr=base + imp_dd.VirtualAddress,
                size=imp_dd.Size,
                sort=MemRegionSort.IMPORT_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

    def _meta_delay_imports(self):
        """Delay Import Directory (Data Directory 13)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            return
        delay_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT")
        if delay_dd is None:
            return
        entries = pe.DIRECTORY_ENTRY_DELAY_IMPORT

        sub_regions: list[MemRegion] = []

        # Delay import descriptor array (including null terminator)
        n_descs = len(entries) + 1
        sub_regions.append(
            StructArray(
                vaddr=base + delay_dd.VirtualAddress,
                entry_size=32,  # sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR)
                count=n_descs,
                sort=MemRegionSort.DELAY_IMPORT_DIRECTORY,
            )
        )

        # Per-DLL delay INT arrays
        for entry in entries:
            int_rva = entry.struct.pINT
            if int_rva:
                n_imports = len(entry.imports) + 1
                sub_regions.append(
                    PointerArray(
                        vaddr=base + int_rva,
                        entry_size=ptr_size,
                        count=n_imports,
                        sort=MemRegionSort.ILT,
                    )
                )

        self.meta_regions.append(
            DataDirectory(
                vaddr=base + delay_dd.VirtualAddress,
                size=delay_dd.Size,
                sort=MemRegionSort.DELAY_IMPORT_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

    def _meta_resources(self):
        """Resource Directory (Data Directory 2)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return
        res_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_RESOURCE")
        if res_dd is None:
            return
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + res_dd.VirtualAddress,
                size=res_dd.Size,
                sort=MemRegionSort.RESOURCE_DIRECTORY,
            )
        )

    def _meta_exceptions(self):
        """Exception Directory (Data Directory 3) - RUNTIME_FUNCTION table."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_EXCEPTION"):
            return
        exc_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_EXCEPTION")
        if exc_dd is None:
            return
        runtime_function_size = 12  # sizeof(RUNTIME_FUNCTION)
        count = exc_dd.Size // runtime_function_size
        sub_regions: list[MemRegion] = []
        if count:
            sub_regions.append(
                StructArray(
                    vaddr=base + exc_dd.VirtualAddress,
                    entry_size=runtime_function_size,
                    count=count,
                    sort=MemRegionSort.EXCEPTION_DIRECTORY,
                )
            )
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + exc_dd.VirtualAddress,
                size=exc_dd.Size,
                sort=MemRegionSort.EXCEPTION_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

    def _meta_base_relocations(self):
        """Base Relocation Directory (Data Directory 5)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        reloc_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_BASERELOC")
        if reloc_dd is None:
            return
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + reloc_dd.VirtualAddress,
                size=reloc_dd.Size,
                sort=MemRegionSort.BASE_RELOCATION,
            )
        )

    def _meta_debug(self):
        """Debug Directory (Data Directory 6)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            return
        dbg_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_DEBUG")
        if dbg_dd is None:
            return
        debug_dir_entry_size = 28  # sizeof(IMAGE_DEBUG_DIRECTORY)
        count = dbg_dd.Size // debug_dir_entry_size
        sub_regions: list[MemRegion] = []
        if count:
            sub_regions.append(
                StructArray(
                    vaddr=base + dbg_dd.VirtualAddress,
                    entry_size=debug_dir_entry_size,
                    count=count,
                    sort=MemRegionSort.DEBUG_DIRECTORY,
                )
            )
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + dbg_dd.VirtualAddress,
                size=dbg_dd.Size,
                sort=MemRegionSort.DEBUG_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

    def _meta_tls(self):
        """TLS Directory (Data Directory 9)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            return
        tls_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_TLS")
        if tls_dd is None:
            return
        tls_dir_size = 40 if is_64 else 24  # sizeof(IMAGE_TLS_DIRECTORY)
        sub_regions: list[MemRegion] = [
            MemRegion(
                vaddr=base + tls_dd.VirtualAddress,
                size=tls_dir_size,
                sort=MemRegionSort.TLS_DIRECTORY,
            )
        ]
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + tls_dd.VirtualAddress,
                size=tls_dd.Size,
                sort=MemRegionSort.TLS_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

    def _meta_load_config(self):
        """Load Config Directory (Data Directory 10)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG"):
            return
        lc_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG")
        if lc_dd is None:
            return
        lc = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct

        sub_regions: list[MemRegion] = []

        # Load config directory structure
        sub_regions.append(
            MemRegion(
                vaddr=base + lc_dd.VirtualAddress,
                size=lc_dd.Size,
                sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
            )
        )

        # SE Handler Table (32-bit only)
        if not is_64 and hasattr(lc, "SEHandlerTable") and hasattr(lc, "SEHandlerCount"):
            if lc.SEHandlerTable and lc.SEHandlerCount:
                sub_regions.append(
                    PointerArray(
                        vaddr=lc.SEHandlerTable,
                        entry_size=4,
                        count=lc.SEHandlerCount,
                        sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
                    )
                )

        # Guard CF Function Table
        if hasattr(lc, "GuardCFFunctionTable") and hasattr(lc, "GuardCFFunctionCount"):
            if lc.GuardCFFunctionTable and lc.GuardCFFunctionCount:
                sub_regions.append(
                    PointerArray(
                        vaddr=lc.GuardCFFunctionTable,
                        entry_size=4,
                        count=lc.GuardCFFunctionCount,
                        sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
                    )
                )

        # Guard Address-Taken IAT Entry Table
        if hasattr(lc, "GuardAddressTakenIatEntryTable") and hasattr(lc, "GuardAddressTakenIatEntryCount"):
            if lc.GuardAddressTakenIatEntryTable and lc.GuardAddressTakenIatEntryCount:
                sub_regions.append(
                    PointerArray(
                        vaddr=lc.GuardAddressTakenIatEntryTable,
                        entry_size=4,
                        count=lc.GuardAddressTakenIatEntryCount,
                        sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
                    )
                )

        # Guard Long Jump Target Table
        if hasattr(lc, "GuardLongJumpTargetTable") and hasattr(lc, "GuardLongJumpTargetCount"):
            if lc.GuardLongJumpTargetTable and lc.GuardLongJumpTargetCount:
                sub_regions.append(
                    PointerArray(
                        vaddr=lc.GuardLongJumpTargetTable,
                        entry_size=4,
                        count=lc.GuardLongJumpTargetCount,
                        sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
                    )
                )

        # Guard EH Continuation Table
        if hasattr(lc, "GuardEHContinuationTable") and hasattr(lc, "GuardEHContinuationCount"):
            if lc.GuardEHContinuationTable and lc.GuardEHContinuationCount:
                sub_regions.append(
                    PointerArray(
                        vaddr=lc.GuardEHContinuationTable,
                        entry_size=4,
                        count=lc.GuardEHContinuationCount,
                        sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
                    )
                )

        self.meta_regions.append(
            DataDirectory(
                vaddr=base + lc_dd.VirtualAddress,
                size=lc_dd.Size,
                sort=MemRegionSort.LOAD_CONFIG_DIRECTORY,
                sub_regions=sub_regions,
            )
        )

    def _meta_bound_imports(self):
        """Bound Import Directory (Data Directory 11)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        if not hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT"):
            return
        bi_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT")
        if bi_dd is None:
            return
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + bi_dd.VirtualAddress,
                size=bi_dd.Size,
                sort=MemRegionSort.BOUND_IMPORT_DIRECTORY,
            )
        )

    def _meta_com_descriptor(self):
        """COM Descriptor / CLR Runtime Header (Data Directory 14)."""
        pe, base, is_64, ptr_size = self._meta_pe_context()
        com_dd = self._meta_dd("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")
        if com_dd is None:
            return
        self.meta_regions.append(
            DataDirectory(
                vaddr=base + com_dd.VirtualAddress,
                size=com_dd.Size,
                sort=MemRegionSort.COM_DESCRIPTOR,
            )
        )

    def __register_relocs(self):
        if not hasattr(self._pe, "DIRECTORY_ENTRY_BASERELOC"):
            log.debug("%s has no relocations", self.binary)
            return []

        for base_reloc in self._pe.DIRECTORY_ENTRY_BASERELOC:
            entry_idx = 0
            while entry_idx < len(base_reloc.entries):
                reloc_data = base_reloc.entries[entry_idx]
                if (
                    reloc_data.type == pefile.RELOCATION_TYPE["IMAGE_REL_BASED_HIGHADJ"]
                ):  # special case, occupies 2 entries
                    if entry_idx == len(base_reloc.entries):
                        log.warning("PE contains corrupt base relocation table")
                        break

                    next_entry = base_reloc.entries[entry_idx]
                    entry_idx += 1
                    reloc = self._make_reloc(addr=reloc_data.rva, reloc_type=reloc_data.type, next_rva=next_entry.rva)
                else:
                    reloc = self._make_reloc(addr=reloc_data.rva, reloc_type=reloc_data.type)

                if reloc is not None:
                    # Some binaries have the DYNAMIC_BASE DllCharacteristic unset but have tons of fixup relocations
                    self.pic = True
                    self.relocs.append(reloc)

                entry_idx += 1

        return self.relocs

    def _make_reloc(self, addr, reloc_type, symbol=None, next_rva=None, resolvewith=None):
        # Handle special cases first
        if reloc_type == 0:  # 0 simply means "ignore this relocation"
            reloc = IMAGE_REL_BASED_ABSOLUTE(owner=self, symbol=symbol, addr=addr, resolvewith=resolvewith)
            return reloc
        if reloc_type is None:  # for DLL imports
            reloc = DllImport(owner=self, symbol=symbol, addr=addr, resolvewith=resolvewith)
            return reloc
        if next_rva is not None:
            reloc = IMAGE_REL_BASED_HIGHADJ(owner=self, addr=addr, next_rva=next_rva)
            return reloc

        # Handle all the normal base relocations
        RelocClass = get_relocation(self.arch.name, reloc_type)
        if RelocClass is None:
            log.debug("Failed to find relocation class for arch %s, type %d", "pe" + self.arch.name, reloc_type)
            return None

        cls = RelocClass(owner=self, symbol=symbol, addr=addr)
        if cls is None:
            log.warning(
                "Failed to retrieve relocation for %s of type %s",
                symbol.name if symbol else "<unknown symbol>",
                reloc_type,
            )

        return cls

    def _register_tls(self):
        if hasattr(self._pe, "DIRECTORY_ENTRY_TLS"):
            tls = self._pe.DIRECTORY_ENTRY_TLS.struct

            self.tls_used = True
            self.tls_data_start = AT.from_lva(tls.StartAddressOfRawData, self).to_rva()
            self.tls_data_size = tls.EndAddressOfRawData - tls.StartAddressOfRawData
            self.tls_index_address = tls.AddressOfIndex
            self.tls_callbacks = (
                self._register_tls_callbacks(tls.AddressOfCallBacks) if tls.AddressOfCallBacks != 0 else []
            )
            self.tls_block_size = self.tls_data_size + tls.SizeOfZeroFill

    def _register_tls_callbacks(self, addr):
        """
        TLS callbacks are stored as an array of virtual addresses to functions.
        The last entry is empty (NULL), which indicates the end of the table
        """
        callbacks = []

        callback_rva = AT.from_lva(addr, self).to_rva()
        is_64bit = self.arch.bits == 64
        ptr_size = 8 if is_64bit else 4
        get_ptr = self._pe.get_qword_at_rva if is_64bit else self._pe.get_dword_at_rva

        callback = get_ptr(callback_rva)
        while callback != 0 and callback is not None:
            callbacks.append(callback)
            callback_rva += ptr_size
            callback = get_ptr(callback_rva)

        return callbacks

    def _read_from_string_table(self, offset: int, encoding: str = "latin-1") -> str:
        """
        Read a null-terminated string from the string table given a byte offset.

        :param offset: Byte offset of the string.
        :param encoding: String encoding (default latin-1).
        """
        assert self._pe.FILE_HEADER is not None
        offset += self._pe.FILE_HEADER.PointerToSymbolTable + self._pe.FILE_HEADER.NumberOfSymbols * 18
        return extract_null_terminated_bytestr(self._raw_data, offset).decode(encoding)

    def _register_sections(self):
        """
        Wrap self._pe.sections in PESection objects, and add them to self.sections.
        """

        for pe_section in self._pe.sections:
            name = pe_section.Name.rstrip(b"\x00").decode("latin-1")
            # Match indirect section names given by a forward slash and a
            # decimal byte offset into the string table.
            str_tbl_offset_match = SECTION_NAME_STRING_TABLE_OFFSET_RE.fullmatch(name)
            if str_tbl_offset_match:
                str_tbl_offset = int(str_tbl_offset_match.group(1))
                name = self._read_from_string_table(str_tbl_offset)
            section = PESection(pe_section, remap_offset=self.linked_base, name=name)
            self.sections.append(section)
            self.sections_map[section.name] = section

    def _find_pdb_path(self):
        """
        Find path to the PDB file containing debug information for this binary.

        Search order:
        1. Embedded path in PE (if exists on disk)
        2. Next to binary with embedded filename
        3. Same name as binary with .pdb extension
        4. debug_symbol_paths (if provided)
        5. Symbol path (_NT_SYMBOL_PATH / SYMBOL_PATH environment variable)
           - Local symbol stores
           - Symbol servers (with download and caching)
        """
        attempts = []

        # Extract PDB info from debug directory for symbol server lookups
        pdb_info = PDBInfo.from_pe(self._pe)

        if pdb_info is not None:
            path = pdb_info.pdb_name
            if os.path.exists(path):
                return path
            attempts.append(path)

            # PDB not at specified location; check next to binary
            if self.binary:
                filename = os.path.basename(path.replace("\\", "/"))
                path = os.path.join(os.path.dirname(self.binary), filename)
                if os.path.exists(path):
                    return path
                attempts.append(path)

        # Guess PDB has same name as binary
        if self.binary:
            path = os.path.splitext(self.binary)[0] + ".pdb"
            if os.path.exists(path):
                return path
            attempts.append(path)

        # Search debug_symbol_paths (user-provided paths)
        if pdb_info and self._debug_symbol_dirs:
            for search_path in self._debug_symbol_dirs:
                if not os.path.exists(search_path):
                    continue

                # Check symbol store layout: path/pdbname/signature/pdbname
                store_path = os.path.join(search_path, pdb_info.pdb_name, pdb_info.signature_id, pdb_info.pdb_name)
                if os.path.exists(store_path):
                    return store_path

                # Check flat layout: path/pdbname
                flat_path = os.path.join(search_path, pdb_info.pdb_name)
                if os.path.exists(flat_path):
                    return flat_path

            attempts.append(f"debug_symbol_paths ({self._debug_symbol_dirs})")

        # Search symbol path (local stores and symbol servers)
        if pdb_info:
            binary_dir = os.path.dirname(self.binary) if self.binary else None
            resolver = SymbolResolver(
                symbol_path_str=self._debug_symbol_path_str,
                local_dirs=[binary_dir] if binary_dir else None,
                download_symbols=self._download_debug_symbols,
                search_microsoft_symserver=self._search_microsoft_symserver,
            )
            symbol_path_result = resolver.find_pdb(
                pdb_info,
                confirm_callback=self._download_debug_symbol_confirm,
                progress_callback=self._download_debug_symbol_progress,
            )
            if symbol_path_result:
                return symbol_path_result
            if resolver.symbol_path_str:
                attempts.append(f"symbol path ({resolver.symbol_path_str})")

        log.warning("Unable to find PDB file for this PE. Tried: %s", str(attempts))
        return None

    def _load_symbols_from_coff_header(self):
        """
        COFF debug info is deprecated, but may still be provided (e.g. by mingw).
        """
        type_to_symbol_type = {
            0: SymbolType.TYPE_OBJECT,
            0x20: SymbolType.TYPE_FUNCTION,
        }

        assert self._pe.FILE_HEADER is not None

        sizeof_symbol_desc = 18

        # Verify symbol table is within file bounds
        end_of_table_offset = (
            self._pe.FILE_HEADER.PointerToSymbolTable + self._pe.FILE_HEADER.NumberOfSymbols * sizeof_symbol_desc
        )
        if end_of_table_offset >= len(self._raw_data):
            log.warning("PE symbol table out of bounds")
            return

        idx = 0
        while idx < self._pe.FILE_HEADER.NumberOfSymbols:
            offset = self._pe.FILE_HEADER.PointerToSymbolTable + idx * sizeof_symbol_desc
            sym_desc = self._raw_data[offset : offset + sizeof_symbol_desc]
            name, value, section, type_, _, num_aux_syms = struct.unpack("<8sIhHBB", sym_desc)
            name_as_dwords = struct.unpack("<II", name)
            if name_as_dwords[0] == 0:
                name = self._read_from_string_table(name_as_dwords[1])
            else:
                name = name.rstrip(b"\x00").decode("latin-1")
            if section > 0 and type_ in type_to_symbol_type and VALID_SYMBOL_NAME_RE.fullmatch(name):
                rva = self._pe.sections[section - 1].VirtualAddress + value
                symbol = WinSymbol(self, name, rva, False, False, None, None, type_to_symbol_type[type_])
                log.debug("Adding symbol %s", symbol)
                self.symbols.add(symbol)
            idx += 1 + num_aux_syms


register_backend("pe", PE)
