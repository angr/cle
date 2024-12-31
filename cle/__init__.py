"""
CLE is an extensible binary loader. Its main goal is to take an executable program and any libraries it depends on and
produce an address space where that program is loaded and ready to run.

The primary interface to CLE is the Loader class.
"""

from __future__ import annotations

__version__ = "9.2.136.dev0"

from .address_translator import AT, AddressTranslator
from .backends import (
    ALL_BACKENDS,
    CGC,
    ELF,
    PE,
    TE,
    XBE,
    Apk,
    BackedCGC,
    Backend,
    Blob,
    Coff,
    ELFCore,
    ExceptionHandling,
    FunctionHint,
    FunctionHintSource,
    Hex,
    Jar,
    MachO,
    MetaELF,
    Minidump,
    NamedRegion,
    Region,
    Regions,
    Section,
    Segment,
    Soot,
    SRec,
    StaticArchive,
    Symbol,
    SymbolSubType,
    SymbolType,
    UefiFirmware,
    register_backend,
)
from .backends.externs import (
    ExternObject,
    ExternSegment,
    KernelObject,
    PointToPrecise,
    TOCRelocation,
)
from .backends.tls import (
    ELFCoreThreadManager,
    ELFThreadManager,
    InternalTLSRelocation,
    MinidumpThreadManager,
    PEThreadManager,
    ThreadManager,
    TLSObject,
)
from .errors import (
    CLECompatibilityError,
    CLEError,
    CLEFileNotFoundError,
    CLEInvalidBinaryError,
    CLEInvalidEncryptionError,
    CLEInvalidFileFormatError,
    CLEMemoryError,
    CLEOperationError,
    CLEUnknownFormatError,
)
from .gdb import GDB_SEARCH_PATH, convert_info_proc_maps, convert_info_sharedlibrary
from .loader import Loader
from .memory import Clemory, ClemoryBase, ClemoryTranslator, ClemoryView
from .patched_stream import PatchedStream

__all__ = [
    "ALL_BACKENDS",
    "CGC",
    "ELF",
    "PE",
    "XBE",
    "Apk",
    "BackedCGC",
    "Backend",
    "Blob",
    "Coff",
    "ELFCore",
    "ExceptionHandling",
    "FunctionHint",
    "FunctionHintSource",
    "Hex",
    "SRec",
    "Jar",
    "MachO",
    "MetaELF",
    "Minidump",
    "NamedRegion",
    "Region",
    "Regions",
    "Section",
    "Segment",
    "Soot",
    "StaticArchive",
    "register_backend",
    "ExternObject",
    "ExternSegment",
    "KernelObject",
    "PointToPrecise",
    "TOCRelocation",
    "ELFCoreThreadManager",
    "ELFThreadManager",
    "InternalTLSRelocation",
    "MinidumpThreadManager",
    "PEThreadManager",
    "ThreadManager",
    "TLSObject",
    "CLECompatibilityError",
    "CLEError",
    "CLEFileNotFoundError",
    "CLEInvalidBinaryError",
    "CLEInvalidEncryptionError",
    "CLEInvalidFileFormatError",
    "CLEOperationError",
    "CLEUnknownFormatError",
    "CLEMemoryError",
    "convert_info_proc_maps",
    "convert_info_sharedlibrary",
    "GDB_SEARCH_PATH",
    "Loader",
    "Clemory",
    "ClemoryBase",
    "ClemoryView",
    "ClemoryTranslator",
    "PatchedStream",
    "AddressTranslator",
    "AT",
    "Symbol",
    "SymbolType",
    "SymbolSubType",
    "TE",
    "UefiFirmware",
]
