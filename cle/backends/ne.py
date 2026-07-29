from __future__ import annotations

import logging
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

import archinfo

from cle.errors import CLEInvalidBinaryError, CLEOperationError
from cle.utils import stream_or_path

from .backend import Backend, FunctionHint, FunctionHintSource, register_backend
from .region import Segment
from .relocation import Relocation
from .symbol import Symbol, SymbolType

log = logging.getLogger(__name__)

__all__ = (
    "NE",
    "NEEntryPoint",
    "NEFixupRecord",
    "NEHeader",
    "NEImportedModule",
    "NEImportedProcedure",
    "NEInternalRelocation",
    "NEName",
    "NERelocation",
    "NESegment",
    "NESymbol",
)


_NE_HEADER_SIZE = 0x40
_SEGMENT_SLOT_SIZE = 0x10000
_MAX_SEGMENTS = 0xFF
_MAX_MODULE_REFERENCES = 4096
_MAX_ENTRY_POINTS = 0xFFFF
_MAX_FIXUP_RECORDS = 0x10000
_MAX_FIXUP_SITES = 0x40000

_SEGMENT_DATA = 0x0001
_SEGMENT_ITERATED = 0x0008
_SEGMENT_MOVABLE = 0x0010
_SEGMENT_SHAREABLE = 0x0020
_SEGMENT_PRELOAD = 0x0040
_SEGMENT_READONLY_OR_EXECUTEONLY = 0x0080
_SEGMENT_RELOCATIONS = 0x0100

_MODULE_DATA_MODE_MASK = 0x0003
_MODULE_LINK_ERROR = 0x2000
_MODULE_LIBRARY = 0x8000

_SOURCE_WIDTHS = {
    0x00: 1,  # low byte
    0x02: 2,  # selector
    0x03: 4,  # 16:16 pointer
    0x05: 2,  # 16-bit offset
}


class _Reader:
    """Small random-access reader which turns every bounds failure into a CLE error."""

    def __init__(self, stream: BinaryIO):
        self._stream = stream
        try:
            original = stream.tell()
            stream.seek(0, os.SEEK_END)
            self.size = stream.tell()
            stream.seek(original)
        except (OSError, OverflowError, ValueError) as exc:
            raise CLEInvalidBinaryError("NE input is not a seekable binary stream") from exc

    def read(self, offset: int, size: int, description: str) -> bytes:
        if offset < 0 or size < 0 or offset > self.size or size > self.size - offset:
            raise CLEInvalidBinaryError(
                f"Truncated NE {description}: range {offset:#x}..{offset + size:#x} exceeds file size {self.size:#x}"
            )
        try:
            self._stream.seek(offset)
            data = self._stream.read(size)
        except (OSError, OverflowError, ValueError) as exc:
            raise CLEInvalidBinaryError(f"Cannot read NE {description} at {offset:#x}") from exc
        if len(data) != size:
            raise CLEInvalidBinaryError(f"Truncated NE {description} at {offset:#x}")
        return data

    def u8(self, offset: int, description: str) -> int:
        return self.read(offset, 1, description)[0]

    def u16(self, offset: int, description: str) -> int:
        return struct.unpack("<H", self.read(offset, 2, description))[0]


@dataclass(frozen=True, slots=True)
class NEHeader:
    """The on-disk Windows NE header, with table offsets left relative to the NE header."""

    offset: int
    linker_version: int
    linker_revision: int
    entry_table_offset: int
    entry_table_size: int
    checksum: int
    flags: int
    automatic_data_segment: int
    heap_size: int
    stack_size: int
    initial_ip: int
    initial_cs: int
    initial_sp: int
    initial_ss: int
    segment_count: int
    module_reference_count: int
    nonresident_name_table_size: int
    segment_table_offset: int
    resource_table_offset: int
    resident_name_table_offset: int
    module_reference_table_offset: int
    imported_name_table_offset: int
    nonresident_name_table_offset: int
    movable_entry_count: int
    alignment_shift: int
    resource_count: int
    target_os: int
    other_flags: int
    fastload_offset: int
    fastload_size: int
    minimum_code_swap_size: int
    expected_windows_version: tuple[int, int]

    @property
    def effective_alignment_shift(self) -> int:
        """The NE format defines a zero alignment field to mean the historical 512-byte default."""
        return self.alignment_shift or 9

    @property
    def is_dll(self) -> bool:
        return bool(self.flags & _MODULE_LIBRARY)


@dataclass(frozen=True, slots=True)
class NEName:
    name: str
    ordinal: int
    resident: bool


@dataclass(frozen=True, slots=True)
class NEImportedModule:
    index: int
    name: str
    normalized_name: str


@dataclass(frozen=True, slots=True)
class NEEntryPoint:
    ordinal: int
    flags: int
    segment_number: int
    offset: int
    rva: int
    movable: bool
    names: tuple[str, ...]

    @property
    def is_exported(self) -> bool:
        return bool(self.flags & 1) or bool(self.names)

    @property
    def uses_shared_data(self) -> bool:
        return bool(self.flags & 2)

    @property
    def parameter_word_count(self) -> int:
        return self.flags >> 3


@dataclass(frozen=True, slots=True)
class NEFixupRecord:
    """One on-disk fixup record, including its fully expanded source chain."""

    segment_number: int
    source_type: int
    additive: bool
    source_offsets: tuple[int, ...]
    source_rvas: tuple[int, ...]
    target_kind: str
    target_segment: int | None = None
    target_offset: int | None = None
    target_rva: int | None = None
    target_entry_ordinal: int | None = None
    module_index: int | None = None
    module_name: str | None = None
    procedure_name: str | None = None
    procedure_ordinal: int | None = None
    os_fixup_type: int | None = None
    os_fixup_value: int | None = None


@dataclass(frozen=True, slots=True)
class NEImportedProcedure:
    module_index: int
    module_name: str
    name: str | None
    ordinal: int | None
    import_key: str
    fixup_rvas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _RawSegment:
    number: int
    sector: int
    file_offset: int
    file_size: int
    initialized_size: int
    flags: int
    memory_size: int
    data: bytes


class NESegment(Segment):
    """A native NE segment placed in a deterministic 64 KiB analysis slot."""

    def __init__(self, raw: _RawSegment):
        super().__init__(raw.file_offset, (raw.number - 1) * _SEGMENT_SLOT_SIZE, raw.file_size, raw.memory_size)
        self.name = f"seg{raw.number:03d}"
        self.segment_number = raw.number
        self.sector = raw.sector
        self.flags = raw.flags
        self.initialized_size = raw.initialized_size

    @property
    def is_iterated(self) -> bool:
        return bool(self.flags & _SEGMENT_ITERATED)

    def addr_to_offset(self, addr):
        # Iterated segment bytes are synthesized from repetition records and do not have a one-to-one file offset.
        return None if self.is_iterated else super().addr_to_offset(addr)

    def offset_to_addr(self, offset):
        # The compressed bytes are a representation of the segment, not bytes at corresponding loaded addresses.
        return None if self.is_iterated else super().offset_to_addr(offset)

    @property
    def is_data(self) -> bool:
        return bool(self.flags & _SEGMENT_DATA)

    @property
    def is_movable(self) -> bool:
        return bool(self.flags & _SEGMENT_MOVABLE)

    @property
    def is_shareable(self) -> bool:
        return bool(self.flags & _SEGMENT_SHAREABLE)

    @property
    def is_preload(self) -> bool:
        return bool(self.flags & _SEGMENT_PRELOAD)

    @property
    def is_readable(self) -> bool:
        return self.is_data or not bool(self.flags & _SEGMENT_READONLY_OR_EXECUTEONLY)

    @property
    def is_writable(self) -> bool:
        return self.is_data and not bool(self.flags & _SEGMENT_READONLY_OR_EXECUTEONLY)

    @property
    def is_executable(self) -> bool:
        return not self.is_data

    @property
    def only_contains_uninitialized_data(self) -> bool:
        return self.initialized_size == 0


class NESymbol(Symbol):
    """An exported or imported NE entry point."""

    def __init__(
        self,
        owner: NE,
        name: str,
        relative_addr: int,
        *,
        is_import: bool,
        is_export: bool,
        ordinal: int | None,
        module_name: str | None = None,
    ):
        super().__init__(owner, name, relative_addr, owner.arch.bytes, SymbolType.TYPE_FUNCTION)
        self.is_import = is_import
        self.is_export = is_export
        self.ordinal = ordinal
        self.module_name = module_name


class _NEFixupRelocation(Relocation):
    """Common application logic for relocations in CLE's deterministic NE analysis address space."""

    __slots__ = ("additive", "source_type")

    def __init__(
        self,
        owner: NE,
        symbol: NESymbol | None,
        relative_addr: int,
        *,
        source_type: int,
        additive: bool,
    ):
        super().__init__(owner, symbol, relative_addr)
        self.source_type = source_type
        self.additive = additive

    def relocate(self):
        if not self.resolved:
            return False

        target = self.value
        if not 0 <= target <= 0xFFFFFFFF:
            raise CLEOperationError(f"NE analysis relocation target {target:#x} does not fit in a 16:16 pointer")
        target_offset = target & 0xFFFF
        target_selector = target >> 16
        memory = self.owner.memory

        if not self.additive:
            if self.source_type == 0x00:
                memory.pack_word(self.dest_addr, target_offset, size=1)
            elif self.source_type == 0x02:
                memory.pack_word(self.dest_addr, target_selector, size=2)
            elif self.source_type == 0x03:
                memory.pack_word(self.dest_addr, target, size=4)
            elif self.source_type == 0x05:
                memory.pack_word(self.dest_addr, target_offset, size=2)
            else:  # pragma: no cover - the parser rejects unsupported source types
                raise CLEOperationError(f"Cannot apply NE source type {self.source_type:#x}")
            return True

        if self.source_type == 0x00:
            current = memory.unpack_word(self.dest_addr, size=1)
            memory.pack_word(self.dest_addr, (current + target_offset) & 0xFF, size=1)
        elif self.source_type == 0x02:
            current = memory.unpack_word(self.dest_addr, size=2)
            if current:
                raise CLEInvalidBinaryError(
                    f"NE additive selector fixup at {self.dest_addr:#x} has nonzero addend {current:#x}"
                )
            memory.pack_word(self.dest_addr, target_selector, size=2)
        elif self.source_type == 0x03:
            current_offset = memory.unpack_word(self.dest_addr, size=2)
            memory.pack_word(self.dest_addr, (current_offset + target_offset) & 0xFFFF, size=2)
            memory.pack_word(self.dest_addr + 2, target_selector, size=2)
        elif self.source_type == 0x05:
            current = memory.unpack_word(self.dest_addr, size=2)
            memory.pack_word(self.dest_addr, (current + target_offset) & 0xFFFF, size=2)
        else:  # pragma: no cover - the parser rejects unsupported source types
            raise CLEOperationError(f"Cannot apply additive NE source type {self.source_type:#x}")
        return True


class NEInternalRelocation(_NEFixupRelocation):
    """A fixup to another location in the same NE module."""

    __slots__ = ("target_rva",)

    def __init__(
        self,
        owner: NE,
        relative_addr: int,
        *,
        target_rva: int,
        source_type: int,
        additive: bool,
    ):
        super().__init__(
            owner,
            None,
            relative_addr,
            source_type=source_type,
            additive=additive,
        )
        self.target_rva = target_rva
        self.resolved = True

    def resolve_symbol(self, solist, **kwargs):  # pylint: disable=unused-argument
        return

    @property
    def value(self) -> int:
        return self.owner.mapped_base + self.target_rva


class NERelocation(_NEFixupRelocation):
    """An imported NE fixup resolved to a module export or a module-qualified analysis extern."""

    __slots__ = (
        "import_key",
        "import_ordinal",
        "module_name",
        "procedure_name",
    )

    def __init__(
        self,
        owner: NE,
        symbol: NESymbol,
        relative_addr: int,
        *,
        module_name: str,
        procedure_name: str | None,
        import_ordinal: int | None,
        source_type: int,
        additive: bool,
        import_key: str,
    ):
        super().__init__(
            owner,
            symbol,
            relative_addr,
            source_type=source_type,
            additive=additive,
        )
        self.module_name = module_name
        self.procedure_name = procedure_name
        self.import_ordinal = import_ordinal
        self.import_key = import_key
        self.resolvewith = module_name

        # Relocation's generic symbol-name key is ambiguous across NE modules. Keep one canonical site per
        # module-qualified procedure in imports; every site remains available through relocs.
        if owner.imports.get(symbol.name) is self:
            del owner.imports[symbol.name]
        owner.imports.setdefault(import_key, self)

    def resolve_symbol(self, solist, extern_object=None, **kwargs):  # pylint: disable=unused-argument
        """Resolve against a matching NE module, or a module-qualified extern when no implementation was loaded."""
        if self.resolved or self.symbol is None:
            return
        wanted_module = NE.normalize_module_name(self.module_name)
        wanted_symbol = f"ordinal.{self.import_ordinal}" if self.import_ordinal is not None else self.procedure_name
        if wanted_symbol is None:
            return
        for obj in solist:
            provides = getattr(obj, "provides", None)
            if provides is None or NE.normalize_module_name(provides) != wanted_module:
                continue
            symbol = obj.get_symbol(wanted_symbol)
            if symbol is not None and symbol.is_export:
                self.resolve(symbol)
                return
        if extern_object is not None:
            self.resolve(
                extern_object.make_extern(
                    self.import_key,
                    sym_type=SymbolType.TYPE_FUNCTION,
                    libname=self.module_name,
                )
            )

    def resolve(self, obj, extern_object=None):  # pylint: disable=unused-argument
        # Every expanded chain site shares one import symbol. Resolve that symbol once while still marking each site.
        if self.symbol is not None and self.symbol.resolved:
            self.resolvedby = self.symbol.resolvedby
            self.resolved = True
            return
        super().resolve(obj, extern_object=extern_object)

    @property
    def value(self) -> int:
        if self.resolvedby is None:
            raise CLEOperationError(f"Unresolved NE import {self.import_key} has no relocation value")
        return self.resolvedby.rebased_addr


class NE(Backend):
    """Loader for 16-bit Windows New Executable (NE) programs and libraries.

    Native ``segment:offset`` addresses are represented in a sparse flat analysis space. Relative to its module,
    segment ``n`` occupies slot ``(n - 1) << 16``. Modules are mapped on 64 KiB boundaries, so the upper half of a
    relocated 16:16 pointer is a deterministic analysis selector and the lower half remains the native segment
    offset. Analysis selectors are address-space tokens, never selectors allocated by a particular Windows runtime.
    """

    is_default = True
    ADDRESS_MODEL = "ne-segment-slot-v1"
    SEGMENT_SLOT_SIZE = _SEGMENT_SLOT_SIZE

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        reader = _Reader(self._binary_stream)
        self.ne_header = self._parse_header(reader)

        # Windows NE does not encode an execution-mode choice in its module flags (bits 2 and 3 are reserved in the
        # Windows 3.1 format). Use protected-mode semantics for the selector-based analysis address model.
        arch_id = "x86:LE:16:Protected Mode"
        try:
            self.set_arch(archinfo.ArchPcode(arch_id))
        except archinfo.ArchError as exc:
            raise CLEInvalidBinaryError(f"Cannot construct the required NE p-code architecture {arch_id!r}") from exc

        self.os = "windows"
        self.mapped_base = self.linked_base = 0
        # Windows allocates selectors for every module at load time. Keep the main object at the historical zero base,
        # but allow dependent NE modules to be placed in disjoint analysis slots.
        self.pic = self.pic or not self.is_main_bin
        self.address_model = self.ADDRESS_MODEL
        self.execution_mode = "protected"
        self.is_dll = self.ne_header.is_dll
        self.automatic_data_segment = self.ne_header.automatic_data_segment
        self.initial_cs = self.ne_header.initial_cs
        self.initial_ip = self.ne_header.initial_ip
        self.initial_ss = self.ne_header.initial_ss
        self.initial_sp = self.ne_header.initial_sp

        raw_segments = self._parse_segment_table(reader)
        segment_list = [NESegment(raw) for raw in raw_segments]
        self.segments = segment_list
        self.sections = self.segments
        self.segments_by_number = {segment.segment_number: segment for segment in segment_list}
        self.sections_map = {segment.name: segment for segment in segment_list}

        self.resident_names = self._parse_name_table(
            reader,
            self.ne_header.offset + self.ne_header.resident_name_table_offset,
            self.ne_header.offset + self.ne_header.module_reference_table_offset,
            resident=True,
        )
        self.nonresident_names = self._parse_nonresident_names(reader)
        self.names = self.resident_names + self.nonresident_names
        self.module_name = self._find_module_name()
        self.module_description = next((item.name for item in self.nonresident_names if item.ordinal == 0), None)

        self.module_references = self._parse_module_references(reader)
        self.imported_modules = tuple(module.normalized_name for module in self.module_references)
        self.deps = [self.module_dependency_name(module.name) for module in self.module_references]
        self.linking = "dynamic" if self.deps else "static"
        self.provides = self.module_dependency_name(self.module_name) if self.is_dll and self.module_name else None

        self.entry_points = self._parse_entry_table(reader)
        self._validate_initial_context()
        self.has_entry_point = self.initial_cs != 0
        self._entry = self.segment_to_rva(self.initial_cs, self.initial_ip) if self.has_entry_point else 0

        self.fixups: tuple[NEFixupRecord, ...]
        self.imported_procedures: tuple[NEImportedProcedure, ...]
        self._load_segments_and_fixups(reader, raw_segments)
        self._register_exports()

    @property
    def mapped_address_bits(self) -> int:
        # Up to 255 logical segments require 24 flat bits. Use the conventional 32-bit analysis container so loaders,
        # CFGs, and serialization do not confuse this with the 16-bit register width.
        return 32

    def rebase(self, new_base):
        # A selector is represented by the upper half of a 16:16 analysis pointer. Keeping every module on a 64 KiB
        # boundary preserves native segment offsets in the lower half.
        if new_base % _SEGMENT_SLOT_SIZE:
            raise CLEOperationError(f"NE analysis base {new_base:#x} is not aligned to 64 KiB")
        super().rebase(new_base)

    def segment_to_selector(self, segment_number: int) -> int:
        """Return CLE's deterministic analysis selector for an NE segment.

        This value is an address-space token, not a selector allocated by a particular Windows runtime.
        """
        rva = self.segment_to_rva(segment_number)
        return (self.mapped_base + rva) >> 16

    @staticmethod
    def normalize_module_name(name: str) -> str:
        normalized = os.path.basename(name).casefold()
        for suffix in (".dll", ".exe", ".drv"):
            if normalized.endswith(suffix):
                return normalized[: -len(suffix)]
        return normalized

    @staticmethod
    def module_dependency_name(name: str) -> str:
        """Return the filename CLE should search for for an imported Windows module."""
        filename = os.path.basename(name).casefold()
        return filename if os.path.splitext(filename)[1] else f"{filename}.dll"

    def segment_to_rva(self, segment_number: int, offset: int = 0) -> int:
        """Encode an NE segment-table number and 16-bit offset as an analysis RVA.

        This validates the logical address, but it intentionally permits offsets beyond a segment's allocation so a
        caller can represent an invalid or one-past address without accidentally changing its segment number.
        Use ``contains_addr`` when mapped-byte membership matters.
        """
        if segment_number not in self.segments_by_number:
            raise ValueError(f"NE segment number {segment_number} is out of range")
        if not 0 <= offset < _SEGMENT_SLOT_SIZE:
            raise ValueError(f"NE segment offset {offset:#x} does not fit in 16 bits")
        return (segment_number - 1) * _SEGMENT_SLOT_SIZE + offset

    def rva_to_segment(self, rva: int) -> tuple[int, int]:
        """Decode an analysis RVA into its NE segment-table number and 16-bit offset."""
        if rva < 0:
            raise ValueError("NE RVA cannot be negative")
        segment_number, offset = divmod(rva, _SEGMENT_SLOT_SIZE)
        segment_number += 1
        if segment_number not in self.segments_by_number:
            raise ValueError(f"NE RVA {rva:#x} is outside the segment-slot address space")
        return segment_number, offset

    def get_symbol(self, name):
        if isinstance(name, str) and name.startswith("ordinal."):
            try:
                return self._ordinal_exports.get(int(name.removeprefix("ordinal.")))
            except ValueError:
                return None
        return super().get_symbol(name)

    @classmethod
    def is_compatible(cls, stream):
        try:
            original = stream.tell()
        except (OSError, ValueError):
            original = 0
        try:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            if size < 0x40:
                return False
            stream.seek(0)
            dos_header = stream.read(0x40)
            if len(dos_header) != 0x40 or not dos_header.startswith(b"MZ"):
                return False
            ne_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
            if ne_offset > size or _NE_HEADER_SIZE > size - ne_offset:
                return False
            stream.seek(ne_offset)
            ne_header = stream.read(_NE_HEADER_SIZE)
            return len(ne_header) == _NE_HEADER_SIZE and ne_header.startswith(b"NE") and ne_header[0x36] == 2
        except (OSError, OverflowError, ValueError):
            return False
        finally:
            try:
                stream.seek(original)
            except (OSError, OverflowError, ValueError):
                pass

    @classmethod
    def check_magic_compatibility(cls, stream):
        return cls.is_compatible(stream)

    @classmethod
    def check_compatibility(cls, spec, obj):
        if not isinstance(obj, NE):
            return False
        try:
            with stream_or_path(spec) as stream:
                return cls.is_compatible(stream)
        except (OSError, OverflowError, ValueError):
            return False

    def _cache_content(self):
        # NE parsing is deliberately bounded and random-access. Do not defeat that by caching an untrusted input.
        return

    @staticmethod
    def _parse_header(reader: _Reader) -> NEHeader:
        dos_header = reader.read(0, 0x40, "DOS header")
        if not dos_header.startswith(b"MZ"):
            raise CLEInvalidBinaryError("NE file does not start with an MZ header")
        ne_offset = struct.unpack_from("<I", dos_header, 0x3C)[0]
        data = reader.read(ne_offset, _NE_HEADER_SIZE, "header")
        if data[:2] != b"NE":
            raise CLEInvalidBinaryError(f"Missing NE signature at DOS e_lfanew {ne_offset:#x}")

        def u16(offset):
            return struct.unpack_from("<H", data, offset)[0]

        def u32(offset):
            return struct.unpack_from("<I", data, offset)[0]

        header = NEHeader(
            offset=ne_offset,
            linker_version=data[2],
            linker_revision=data[3],
            entry_table_offset=u16(4),
            entry_table_size=u16(6),
            checksum=u32(8),
            flags=u16(0x0C),
            automatic_data_segment=u16(0x0E),
            heap_size=u16(0x10),
            stack_size=u16(0x12),
            initial_ip=u16(0x14),
            initial_cs=u16(0x16),
            initial_sp=u16(0x18),
            initial_ss=u16(0x1A),
            segment_count=u16(0x1C),
            module_reference_count=u16(0x1E),
            nonresident_name_table_size=u16(0x20),
            segment_table_offset=u16(0x22),
            resource_table_offset=u16(0x24),
            resident_name_table_offset=u16(0x26),
            module_reference_table_offset=u16(0x28),
            imported_name_table_offset=u16(0x2A),
            nonresident_name_table_offset=u32(0x2C),
            movable_entry_count=u16(0x30),
            alignment_shift=u16(0x32),
            resource_count=u16(0x34),
            target_os=data[0x36],
            other_flags=data[0x37],
            fastload_offset=u16(0x38),
            fastload_size=u16(0x3A),
            minimum_code_swap_size=u16(0x3C),
            expected_windows_version=(data[0x3F], data[0x3E]),
        )

        if header.target_os != 2:
            raise CLEInvalidBinaryError(f"NE target OS {header.target_os} is not 16-bit Windows")
        if not 1 <= header.segment_count <= _MAX_SEGMENTS:
            raise CLEInvalidBinaryError(f"Invalid NE segment count {header.segment_count}")
        if header.module_reference_count > _MAX_MODULE_REFERENCES:
            raise CLEInvalidBinaryError(
                f"NE module reference count {header.module_reference_count} exceeds the safety limit"
            )
        if header.alignment_shift > 15:
            raise CLEInvalidBinaryError(f"Invalid NE alignment shift {header.alignment_shift}")
        if header.flags & _MODULE_LINK_ERROR:
            raise CLEInvalidBinaryError("NE header reports link-time errors")
        if header.flags & _MODULE_DATA_MODE_MASK == _MODULE_DATA_MODE_MASK:
            raise CLEInvalidBinaryError("NE header has both single-data and multiple-data flags set")
        if not header.flags & _MODULE_DATA_MODE_MASK and header.automatic_data_segment != 0:
            raise CLEInvalidBinaryError("NE automatic data segment is set while the module declares no automatic data")
        if header.entry_table_size == 0:
            raise CLEInvalidBinaryError("NE entry table is empty")

        segment_start = ne_offset + header.segment_table_offset
        segment_end = segment_start + header.segment_count * 8
        resource_start = ne_offset + header.resource_table_offset
        resident_start = ne_offset + header.resident_name_table_offset
        module_start = ne_offset + header.module_reference_table_offset
        imported_start = ne_offset + header.imported_name_table_offset
        entry_start = ne_offset + header.entry_table_offset
        if header.segment_table_offset < _NE_HEADER_SIZE:
            raise CLEInvalidBinaryError("NE segment table overlaps the fixed header")
        if not (segment_end <= resource_start <= resident_start <= module_start <= imported_start <= entry_start):
            raise CLEInvalidBinaryError("NE metadata tables are out of order or overlap")
        if module_start + header.module_reference_count * 2 > imported_start:
            raise CLEInvalidBinaryError("NE module reference table overlaps the imported-name table")
        reader.read(entry_start, header.entry_table_size, "entry table")
        # Touch each boundary so an overflow/truncation is rejected before any segment is mapped.
        reader.read(segment_start, header.segment_count * 8, "segment table")
        reader.read(resource_start, resident_start - resource_start, "resource table")
        reader.read(resident_start, module_start - resident_start, "resident-name table")
        reader.read(module_start, header.module_reference_count * 2, "module reference table")
        reader.read(imported_start, entry_start - imported_start, "imported-name table")
        return header

    @staticmethod
    def _expand_iterated_segment(data: bytes, segment_number: int) -> bytes:
        result = bytearray()
        cursor = 0
        while cursor < len(data):
            if len(data) - cursor < 4:
                raise CLEInvalidBinaryError(f"Truncated NE iterated-data record in segment {segment_number}")
            iterations, size = struct.unpack_from("<HH", data, cursor)
            cursor += 4
            if size > len(data) - cursor:
                raise CLEInvalidBinaryError(f"Truncated NE iterated-data payload in segment {segment_number}")
            expanded_size = iterations * size
            if expanded_size > _SEGMENT_SLOT_SIZE - len(result):
                raise CLEInvalidBinaryError(f"Expanded NE iterated segment {segment_number} exceeds 64 KiB")
            pattern = data[cursor : cursor + size]
            cursor += size
            result.extend(pattern * iterations)
        return bytes(result)

    def _parse_segment_table(self, reader: _Reader) -> list[_RawSegment]:
        table = reader.read(
            self.ne_header.offset + self.ne_header.segment_table_offset,
            self.ne_header.segment_count * 8,
            "segment table",
        )
        result = []
        for index in range(self.ne_header.segment_count):
            sector, length, flags, minimum_allocation = struct.unpack_from("<4H", table, index * 8)
            number = index + 1
            file_offset = sector << self.ne_header.effective_alignment_shift if sector else 0
            file_size = (length or _SEGMENT_SLOT_SIZE) if sector else 0
            data = reader.read(file_offset, file_size, f"segment {number} data") if file_size else b""
            initialized_data = self._expand_iterated_segment(data, number) if flags & _SEGMENT_ITERATED else data
            initialized_size = len(initialized_data)
            memory_size = max(initialized_size, minimum_allocation or _SEGMENT_SLOT_SIZE)
            if memory_size > _SEGMENT_SLOT_SIZE:
                raise CLEInvalidBinaryError(f"NE segment {number} exceeds 64 KiB")
            if flags & _SEGMENT_RELOCATIONS and file_size == 0:
                raise CLEInvalidBinaryError(f"Uninitialized NE segment {number} has a relocation table")
            result.append(
                _RawSegment(
                    number,
                    sector,
                    file_offset,
                    file_size,
                    initialized_size,
                    flags,
                    memory_size,
                    initialized_data,
                )
            )
        return result

    @staticmethod
    def _decode_name(raw: bytes, description: str) -> str:
        if not raw or b"\0" in raw:
            raise CLEInvalidBinaryError(f"Invalid empty or NUL-containing NE {description}")
        return raw.decode("latin-1")

    def _parse_name_table(self, reader: _Reader, start: int, end: int, *, resident: bool) -> tuple[NEName, ...]:
        if end < start:
            raise CLEInvalidBinaryError("Invalid NE name-table range")
        data = reader.read(start, end - start, "resident-name table" if resident else "nonresident-name table")
        result = []
        cursor = 0
        terminated = False
        while cursor < len(data):
            length = data[cursor]
            cursor += 1
            if length == 0:
                terminated = True
                break
            if cursor + length + 2 > len(data):
                raise CLEInvalidBinaryError("Truncated NE name-table entry")
            name = self._decode_name(data[cursor : cursor + length], "export name")
            cursor += length
            ordinal = struct.unpack_from("<H", data, cursor)[0]
            cursor += 2
            result.append(NEName(name, ordinal, resident))
        if not terminated:
            raise CLEInvalidBinaryError("NE name table has no terminator")
        if any(data[cursor:]):
            raise CLEInvalidBinaryError("NE name table has nonzero data after its terminator")
        return tuple(result)

    def _parse_nonresident_names(self, reader: _Reader) -> tuple[NEName, ...]:
        size = self.ne_header.nonresident_name_table_size
        offset = self.ne_header.nonresident_name_table_offset
        if size == 0:
            return ()
        if offset == 0:
            raise CLEInvalidBinaryError("NE nonresident-name table has a size but no file offset")
        return self._parse_name_table(reader, offset, offset + size, resident=False)

    def _find_module_name(self) -> str | None:
        names = [item.name for item in self.resident_names if item.ordinal == 0]
        if len(names) > 1:
            raise CLEInvalidBinaryError("NE resident-name table defines multiple module names")
        if names:
            return names[0]
        if self.binary is not None:
            return os.path.splitext(os.path.basename(self.binary))[0]
        return None

    def _read_imported_name(self, reader: _Reader, relative_offset: int, description: str) -> str:
        table_start = self.ne_header.offset + self.ne_header.imported_name_table_offset
        table_end = self.ne_header.offset + self.ne_header.entry_table_offset
        if relative_offset < 0 or relative_offset >= table_end - table_start:
            raise CLEInvalidBinaryError(f"NE {description} offset {relative_offset:#x} is outside imported-name table")
        length = reader.u8(table_start + relative_offset, description)
        if length == 0 or relative_offset + 1 + length > table_end - table_start:
            raise CLEInvalidBinaryError(f"Invalid NE {description} at imported-name offset {relative_offset:#x}")
        return self._decode_name(reader.read(table_start + relative_offset + 1, length, description), description)

    def _parse_module_references(self, reader: _Reader) -> tuple[NEImportedModule, ...]:
        start = self.ne_header.offset + self.ne_header.module_reference_table_offset
        result = []
        seen = set()
        for index in range(1, self.ne_header.module_reference_count + 1):
            name_offset = reader.u16(start + (index - 1) * 2, f"module reference {index}")
            name = self._read_imported_name(reader, name_offset, f"module reference {index}")
            normalized = self.normalize_module_name(name)
            if not normalized:
                raise CLEInvalidBinaryError(f"NE module reference {index} has an empty normalized name")
            if normalized in seen:
                log.debug("NE module %s is referenced more than once", name)
            seen.add(normalized)
            result.append(NEImportedModule(index, name, normalized))
        return tuple(result)

    def _parse_entry_table(self, reader: _Reader) -> dict[int, NEEntryPoint]:
        data = reader.read(
            self.ne_header.offset + self.ne_header.entry_table_offset,
            self.ne_header.entry_table_size,
            "entry table",
        )
        names_by_ordinal: dict[int, list[str]] = {}
        for item in self.names:
            if item.ordinal:
                names_by_ordinal.setdefault(item.ordinal, []).append(item.name)

        result = {}
        cursor = 0
        ordinal = 1
        movable_count = 0
        terminated = False
        while cursor < len(data):
            count = data[cursor]
            cursor += 1
            if count == 0:
                terminated = True
                break
            if cursor >= len(data):
                raise CLEInvalidBinaryError("Truncated NE entry-table bundle header")
            segment_indicator = data[cursor]
            cursor += 1
            if ordinal + count - 1 > _MAX_ENTRY_POINTS:
                raise CLEInvalidBinaryError("NE entry table contains too many ordinals")
            if segment_indicator == 0:
                ordinal += count
                continue
            record_size = 6 if segment_indicator == 0xFF else 3
            if cursor + count * record_size > len(data):
                raise CLEInvalidBinaryError("Truncated NE entry-table bundle")
            for _ in range(count):
                flags = data[cursor]
                if segment_indicator == 0xFF:
                    int_3f = struct.unpack_from("<H", data, cursor + 1)[0]
                    if int_3f != 0x3FCD:
                        raise CLEInvalidBinaryError(f"Invalid movable NE entry thunk for ordinal {ordinal}")
                    segment_number = data[cursor + 3]
                    offset = struct.unpack_from("<H", data, cursor + 4)[0]
                    movable = True
                    movable_count += 1
                else:
                    segment_number = segment_indicator
                    offset = struct.unpack_from("<H", data, cursor + 1)[0]
                    movable = False
                cursor += record_size
                segment = self.segments_by_number.get(segment_number)
                if segment is None or not segment.is_executable:
                    raise CLEInvalidBinaryError(
                        f"NE entry ordinal {ordinal} refers to invalid code segment {segment_number}"
                    )
                if offset >= segment.initialized_size:
                    raise CLEInvalidBinaryError(
                        f"NE entry ordinal {ordinal} offset {offset:#x} is outside initialized segment {segment_number}"
                    )
                result[ordinal] = NEEntryPoint(
                    ordinal,
                    flags,
                    segment_number,
                    offset,
                    self.segment_to_rva(segment_number, offset),
                    movable,
                    tuple(names_by_ordinal.get(ordinal, ())),
                )
                ordinal += 1
        if not terminated:
            raise CLEInvalidBinaryError("NE entry table has no terminator")
        if any(data[cursor:]):
            raise CLEInvalidBinaryError("NE entry table has nonzero data after its terminator")
        if movable_count != self.ne_header.movable_entry_count:
            raise CLEInvalidBinaryError(
                f"NE entry table has {movable_count} movable entries, "
                f"header declares {self.ne_header.movable_entry_count}"
            )
        for named_ordinal in names_by_ordinal:
            if named_ordinal not in result:
                raise CLEInvalidBinaryError(f"NE export name refers to missing entry ordinal {named_ordinal}")
        return result

    def _validate_initial_context(self):
        header = self.ne_header
        if header.automatic_data_segment:
            segment = self.segments_by_number.get(header.automatic_data_segment)
            if segment is None or not segment.is_data:
                raise CLEInvalidBinaryError("NE automatic data segment does not refer to a data segment")
            if segment.memsize + header.heap_size + header.stack_size > _SEGMENT_SLOT_SIZE:
                raise CLEInvalidBinaryError("NE automatic data, heap, and stack exceed 64 KiB")
        elif header.flags & _MODULE_DATA_MODE_MASK:
            raise CLEInvalidBinaryError("NE module declares automatic data but has no automatic data segment")

        if header.initial_cs == 0:
            if not header.is_dll:
                raise CLEInvalidBinaryError("NE executable has no initial CS")
        else:
            code = self.segments_by_number.get(header.initial_cs)
            if code is None or not code.is_executable or header.initial_ip >= code.initialized_size:
                raise CLEInvalidBinaryError("NE initial CS:IP does not refer to mapped code")

        if header.initial_ss == 0:
            if not header.is_dll:
                raise CLEInvalidBinaryError("NE executable has no initial SS")
        else:
            stack = self.segments_by_number.get(header.initial_ss)
            if stack is None or not stack.is_data:
                raise CLEInvalidBinaryError("NE initial SS does not refer to a data segment")
            stack_limit = stack.memsize + (
                header.stack_size if header.initial_ss == header.automatic_data_segment else 0
            )
            if header.initial_sp and header.initial_sp > stack_limit:
                raise CLEInvalidBinaryError("NE initial SP exceeds the stack segment")

    @staticmethod
    def _expand_fixup_chain(data: bytes, head: int, width: int, *, additive: bool) -> tuple[int, ...]:
        if additive:
            if head == 0xFFFF or head + width > len(data):
                raise CLEInvalidBinaryError(f"NE additive fixup source {head:#x} is outside initialized segment data")
            return (head,)

        result = []
        seen = set()
        current = head
        while current != 0xFFFF:
            if current in seen:
                raise CLEInvalidBinaryError(f"Cycle in NE fixup chain at segment offset {current:#x}")
            if current + max(width, 2) > len(data):
                raise CLEInvalidBinaryError(f"NE fixup-chain source {current:#x} is outside initialized segment data")
            seen.add(current)
            result.append(current)
            if len(result) > _MAX_FIXUP_SITES:
                raise CLEInvalidBinaryError("NE fixup chain exceeds the safety limit")
            current = struct.unpack_from("<H", data, current)[0]
        if not result:
            raise CLEInvalidBinaryError("NE fixup record has an empty source chain")
        return tuple(result)

    def _parse_fixup_target(
        self,
        reader: _Reader,
        target_kind: int,
        target_1: int,
        target_2: int,
    ) -> dict:
        if target_kind == 0:
            if target_1 == 0x00FF:
                entry = self.entry_points.get(target_2)
                if entry is None:
                    raise CLEInvalidBinaryError(f"NE internal fixup refers to missing movable ordinal {target_2}")
                return {
                    "target_kind": "internal",
                    "target_segment": entry.segment_number,
                    "target_offset": entry.offset,
                    "target_rva": entry.rva,
                    "target_entry_ordinal": target_2,
                }
            if target_1 & 0xFF00:
                raise CLEInvalidBinaryError("NE internal fixup has a nonzero reserved segment byte")
            segment_number = target_1 & 0xFF
            segment = self.segments_by_number.get(segment_number)
            if segment is None or target_2 >= segment.memsize:
                raise CLEInvalidBinaryError("NE internal fixup target is outside a mapped segment")
            return {
                "target_kind": "internal",
                "target_segment": segment_number,
                "target_offset": target_2,
                "target_rva": self.segment_to_rva(segment_number, target_2),
            }

        if target_kind in (1, 2):
            if not 1 <= target_1 <= len(self.module_references):
                raise CLEInvalidBinaryError(f"NE import fixup has invalid module index {target_1}")
            module = self.module_references[target_1 - 1]
            if target_kind == 1:
                if target_2 == 0:
                    raise CLEInvalidBinaryError("NE import-by-ordinal fixup uses ordinal zero")
                return {
                    "target_kind": "import_ordinal",
                    "module_index": module.index,
                    "module_name": module.normalized_name,
                    "procedure_ordinal": target_2,
                }
            name = self._read_imported_name(reader, target_2, "imported procedure name")
            return {
                "target_kind": "import_name",
                "module_index": module.index,
                "module_name": module.normalized_name,
                "procedure_name": name,
            }

        return {"target_kind": "os_fixup", "os_fixup_type": target_1, "os_fixup_value": target_2}

    def _load_segments_and_fixups(self, reader: _Reader, raw_segments: list[_RawSegment]):
        fixups = []
        disk_ranges = []
        imported_sites: dict[tuple[int, str | None, int | None], list[int]] = {}
        import_symbols: dict[tuple[int, str | None, int | None], NESymbol] = {}
        total_sites = 0

        metadata_end = self.ne_header.offset + self.ne_header.entry_table_offset + self.ne_header.entry_table_size
        if self.ne_header.nonresident_name_table_size:
            nonresident_start = self.ne_header.nonresident_name_table_offset
            disk_ranges.append(
                (
                    nonresident_start,
                    nonresident_start + self.ne_header.nonresident_name_table_size,
                    "nonresident-name table",
                )
            )
        for raw in raw_segments:
            segment = self.segments_by_number[raw.number]
            data = raw.data
            if raw.file_size and raw.file_offset < metadata_end:
                raise CLEInvalidBinaryError(f"NE segment {raw.number} data overlaps executable metadata")

            mapped = data + bytes(raw.memory_size - len(data))
            self.memory.add_backer(segment.vaddr, mapped)

            range_end = raw.file_offset + raw.file_size
            if raw.file_size:
                disk_ranges.append((raw.file_offset, range_end, f"segment {raw.number}"))
            if not raw.flags & _SEGMENT_RELOCATIONS:
                continue

            count = reader.u16(range_end, f"segment {raw.number} relocation count")
            if count > _MAX_FIXUP_RECORDS:
                raise CLEInvalidBinaryError(f"NE segment {raw.number} has too many fixup records")
            table_size = 2 + count * 8
            table = reader.read(range_end, table_size, f"segment {raw.number} relocation table")
            disk_ranges[-1] = (raw.file_offset, range_end + table_size, f"segment {raw.number}")

            for index in range(count):
                source_type_raw, flags, source_head, target_1, target_2 = struct.unpack_from(
                    "<BBHHH", table, 2 + index * 8
                )
                # Some Windows linkers set the otherwise-unused high bit. The Win16 loader ignores it when selecting
                # the address operation, as does Wine; retain that compatibility without accepting unknown base types.
                source_type = source_type_raw & 0x7F
                if source_type not in _SOURCE_WIDTHS:
                    raise CLEInvalidBinaryError(
                        f"NE segment {raw.number} fixup {index} has unsupported source type {source_type_raw:#x}"
                    )
                if flags & ~0x07:
                    raise CLEInvalidBinaryError(
                        f"NE segment {raw.number} fixup {index} has unsupported flags {flags:#x}"
                    )
                additive = bool(flags & 4)
                source_offsets = self._expand_fixup_chain(
                    data, source_head, _SOURCE_WIDTHS[source_type], additive=additive
                )
                total_sites += len(source_offsets)
                if total_sites > _MAX_FIXUP_SITES:
                    raise CLEInvalidBinaryError("NE image has too many expanded fixup sites")
                source_rvas = tuple(self.segment_to_rva(raw.number, offset) for offset in source_offsets)
                target = self._parse_fixup_target(reader, flags & 3, target_1, target_2)
                record = NEFixupRecord(
                    segment_number=raw.number,
                    source_type=source_type,
                    additive=additive,
                    source_offsets=source_offsets,
                    source_rvas=source_rvas,
                    **target,
                )
                fixups.append(record)

                if record.target_rva is not None:
                    for source_rva in source_rvas:
                        self.relocs.append(
                            NEInternalRelocation(
                                self,
                                source_rva,
                                target_rva=record.target_rva,
                                source_type=source_type,
                                additive=additive,
                            )
                        )

                if record.module_index is None:
                    continue
                symbol_key = (record.module_index, record.procedure_name, record.procedure_ordinal)
                imported_sites.setdefault(symbol_key, []).extend(source_rvas)
                symbol = import_symbols.get(symbol_key)
                procedure_key = (
                    record.procedure_name
                    if record.procedure_name is not None
                    else f"ordinal.{record.procedure_ordinal}"
                )
                assert procedure_key is not None and record.module_name is not None
                import_key = f"{record.module_name}!{procedure_key}"
                if symbol is None:
                    symbol = NESymbol(
                        self,
                        procedure_key,
                        0,
                        is_import=True,
                        is_export=False,
                        ordinal=record.procedure_ordinal,
                        module_name=record.module_name,
                    )
                    import_symbols[symbol_key] = symbol
                    self.symbols.add(symbol)
                for source_rva in source_rvas:
                    self.relocs.append(
                        NERelocation(
                            self,
                            symbol,
                            source_rva,
                            module_name=record.module_name,
                            procedure_name=record.procedure_name,
                            import_ordinal=record.procedure_ordinal,
                            source_type=source_type,
                            additive=additive,
                            import_key=import_key,
                        )
                    )

        disk_ranges.sort()
        for (_, previous_end, previous_name), (current_start, _, current_name) in zip(disk_ranges, disk_ranges[1:]):
            if current_start < previous_end:
                raise CLEInvalidBinaryError(f"Overlapping NE disk ranges for {previous_name} and {current_name}")

        procedures = []
        for (module_index, name, ordinal), sites in imported_sites.items():
            module = self.module_references[module_index - 1]
            procedure_key = name if name is not None else f"ordinal.{ordinal}"
            procedures.append(
                NEImportedProcedure(
                    module_index,
                    module.normalized_name,
                    name,
                    ordinal,
                    f"{module.normalized_name}!{procedure_key}",
                    tuple(sites),
                )
            )
        self.fixups = tuple(fixups)
        self.imported_procedures = tuple(procedures)
        self.jmprel = {procedure.import_key: procedure.fixup_rvas[0] for procedure in self.imported_procedures}

    def _register_exports(self):
        self._ordinal_exports = {}
        exported_names = set()
        for ordinal, entry in self.entry_points.items():
            hint_name = entry.names[0] if entry.names else (f"ordinal.{ordinal}" if entry.is_exported else None)
            self.function_hints.append(FunctionHint(entry.rva, 0, FunctionHintSource.EXPORT_TABLE, name=hint_name))
            if not entry.is_exported:
                continue
            ordinal_name = f"ordinal.{ordinal}"
            ordinal_symbol = NESymbol(
                self,
                ordinal_name,
                entry.rva,
                is_import=False,
                is_export=True,
                ordinal=ordinal,
            )
            self.symbols.add(ordinal_symbol)
            self._ordinal_exports[ordinal] = ordinal_symbol
            for name in entry.names:
                if name in exported_names:
                    raise CLEInvalidBinaryError(f"Duplicate NE export name {name!r}")
                exported_names.add(name)
                self.symbols.add(
                    NESymbol(
                        self,
                        name,
                        entry.rva,
                        is_import=False,
                        is_export=True,
                        ordinal=ordinal,
                    )
                )


register_backend("ne", NE)
