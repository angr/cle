from __future__ import annotations

import io
import struct

import pytest

import cle
from cle.backends.ne import NEInternalRelocation


def _name_entry(name: bytes, ordinal: int) -> bytes:
    return bytes([len(name)]) + name + struct.pack("<H", ordinal)


def _minimal_ne(
    *,
    with_import: bool = False,
    cyclic_fixup: bool = False,
    first_segment_data: bytes | None = None,
    first_segment_flags: int = 0,
    first_segment_minimum: int | None = None,
    relocation_records: tuple[bytes, ...] | None = None,
    module_name: bytes = b"SYNTH",
    import_module: bytes = b"KERNEL",
    import_name: bytes = b"FOO",
    is_dll: bool = False,
    module_flags: int = 0,
) -> bytes:
    ne_offset = 0x40
    segment_table = 0x40
    resource_table = 0x50
    resident_table = 0x54

    resident_names = _name_entry(module_name, 0) + _name_entry(b"Start", 1) + b"\0"
    module_table = resident_table + len(resident_names)
    imported_table = module_table + (2 if with_import else 0)
    imported_names = (
        bytes([len(import_module)]) + import_module + bytes([len(import_name)]) + import_name if with_import else b""
    )
    entry_table = imported_table + len(imported_names)
    entries = b"\x01\x01\x01\x00\x00\x00"  # one fixed entry in segment 1, followed by the terminator

    metadata_end = ne_offset + entry_table + len(entries)
    first_segment_offset = (metadata_end + 0x0F) & ~0x0F
    if first_segment_data is None:
        first_segment_data = b"\x02\x00\x00\x00" if cyclic_fixup else b"\x02\x00\xff\xff"
        if not with_import:
            first_segment_data = b"\x55\x8b\xec\xc3"
    if relocation_records is None:
        procedure_offset = 1 + len(import_module)
        relocation_records = (
            (struct.pack("<BBHHH", 5, 2, 0, 1, procedure_offset),) if with_import else ()
        )  # import by name through the 0 -> 2 -> ffff source chain
    relocation_table = (
        struct.pack("<H", len(relocation_records)) + b"".join(relocation_records) if relocation_records else b""
    )
    second_segment_offset = (first_segment_offset + len(first_segment_data) + len(relocation_table) + 0x0F) & ~0x0F
    second_segment_data = b"\x01\x02\x03\x04"

    result = bytearray(second_segment_offset + len(second_segment_data))
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, ne_offset)

    header = memoryview(result)[ne_offset : ne_offset + 0x40]
    header[:2] = b"NE"
    header[2] = 5
    header[3] = 1
    struct.pack_into("<H", header, 0x04, entry_table)
    struct.pack_into("<H", header, 0x06, len(entries))
    struct.pack_into("<H", header, 0x0C, (0x8001 if is_dll else 2) | module_flags)
    struct.pack_into("<H", header, 0x0E, 2)  # automatic data is segment 2
    struct.pack_into("<HH", header, 0x14, 0, 1)  # CS:IP = segment 1:0
    struct.pack_into("<HH", header, 0x18, 4, 2)  # SS:SP = segment 2:4
    struct.pack_into("<HH", header, 0x1C, 2, 1 if with_import else 0)
    struct.pack_into("<H", header, 0x22, segment_table)
    struct.pack_into("<H", header, 0x24, resource_table)
    struct.pack_into("<H", header, 0x26, resident_table)
    struct.pack_into("<H", header, 0x28, module_table)
    struct.pack_into("<H", header, 0x2A, imported_table)
    struct.pack_into("<H", header, 0x32, 4)
    header[0x36] = 2  # Windows
    header[0x3E] = 10
    header[0x3F] = 3

    segment_flags = first_segment_flags | (0x100 if relocation_records else 0)
    if first_segment_minimum is None:
        first_segment_minimum = len(first_segment_data)
    struct.pack_into(
        "<4H",
        result,
        ne_offset + segment_table,
        first_segment_offset >> 4,
        len(first_segment_data),
        segment_flags,
        first_segment_minimum,
    )
    struct.pack_into(
        "<4H",
        result,
        ne_offset + segment_table + 8,
        second_segment_offset >> 4,
        len(second_segment_data),
        1,
        len(second_segment_data),
    )

    struct.pack_into("<HH", result, ne_offset + resource_table, 4, 0)
    result[ne_offset + resident_table : ne_offset + resident_table + len(resident_names)] = resident_names
    if with_import:
        struct.pack_into("<H", result, ne_offset + module_table, 0)
    result[ne_offset + imported_table : ne_offset + imported_table + len(imported_names)] = imported_names
    result[ne_offset + entry_table : ne_offset + entry_table + len(entries)] = entries
    result[first_segment_offset : first_segment_offset + len(first_segment_data)] = first_segment_data
    result[
        first_segment_offset
        + len(first_segment_data) : first_segment_offset
        + len(first_segment_data)
        + len(relocation_table)
    ] = relocation_table
    result[second_segment_offset : second_segment_offset + len(second_segment_data)] = second_segment_data
    return bytes(result)


def _load(data: bytes, **kwargs) -> cle.Loader:
    return cle.Loader(io.BytesIO(data), auto_load_libs=False, **kwargs)


def test_loads_segmented_ne_with_native_16_bit_architecture():
    data = _minimal_ne()
    stream = io.BytesIO(data)
    stream.seek(7)
    assert cle.NE.is_compatible(stream)
    assert stream.tell() == 7

    loader = _load(data)
    obj = loader.main_object

    assert isinstance(obj, cle.NE)
    assert obj.arch.name == "x86:LE:16:Protected Mode"
    assert obj.arch.bits == 16
    assert obj.mapped_address_bits == 32
    assert obj.address_model == "ne-segment-slot-v1"
    assert obj.entry == 0
    assert obj.max_addr == 0x10003  # deliberately beyond the native 16-bit register width
    assert obj.module_name == "SYNTH"
    assert obj.cached_content is None

    assert len(obj.segments) == 2
    assert obj.segments[0].segment_number == 1
    assert obj.segments[0].is_executable
    assert obj.segments[1].segment_number == 2
    assert obj.segments[1].is_writable
    assert obj.memory.load(0, 4) == b"\x55\x8b\xec\xc3"
    assert obj.memory.load(0x10000, 4) == b"\x01\x02\x03\x04"

    assert obj.segment_to_rva(2, 3) == 0x10003
    assert obj.rva_to_segment(0x10003) == (2, 3)
    with pytest.raises(ValueError, match="segment number"):
        obj.segment_to_rva(3)
    with pytest.raises(ValueError, match="16 bits"):
        obj.segment_to_rva(1, 0x10000)

    entry = obj.entry_points[1]
    assert entry.rva == 0
    assert entry.names == ("Start",)
    assert obj.get_symbol("Start").rebased_addr == 0
    assert obj.get_symbol("ordinal.1").rebased_addr == 0
    assert [(hint.addr, hint.name) for hint in obj.function_hints] == [(0, "Start")]


def test_expands_import_fixup_chains_into_module_qualified_externs():
    loader = _load(_minimal_ne(with_import=True))
    obj = loader.main_object

    assert isinstance(obj, cle.NE)
    assert obj.imported_modules == ("kernel",)
    assert obj.deps == ["kernel.dll"]
    assert len(obj.fixups) == 1
    assert obj.fixups[0].source_offsets == (0, 2)
    assert obj.fixups[0].source_rvas == (0, 2)
    assert obj.fixups[0].target_kind == "import_name"
    assert obj.fixups[0].module_name == "kernel"
    assert obj.fixups[0].procedure_name == "FOO"

    assert len(obj.imported_procedures) == 1
    procedure = obj.imported_procedures[0]
    assert procedure.import_key == "kernel!FOO"
    assert procedure.fixup_rvas == (0, 2)
    assert list(obj.imports) == ["kernel!FOO"]
    assert len(obj.relocs) == 2
    assert all(relocation.resolved for relocation in obj.relocs)
    assert len(loader.all_objects) == 2
    assert all(relocation.resolvedby.name == "kernel!FOO" for relocation in obj.relocs)
    assert [symbol.name for symbol in obj.resolved_imports] == ["FOO"]
    target_offset = obj.relocs[0].value & 0xFFFF
    assert obj.memory.load(0, 4) == struct.pack("<HH", target_offset, target_offset)


def test_applies_internal_fixup_source_types_and_addends():
    segment_data = bytearray(24)
    struct.pack_into("<H", segment_data, 0, 4)
    struct.pack_into("<H", segment_data, 4, 0xFFFF)
    struct.pack_into("<H", segment_data, 8, 0xFFFF)
    struct.pack_into("<H", segment_data, 10, 0xFFFF)
    struct.pack_into("<H", segment_data, 12, 3)
    segment_data[14] = 0xFF
    struct.pack_into("<H", segment_data, 15, 0xFFFF)
    struct.pack_into("<HH", segment_data, 17, 0xFFFF, 0xABCD)
    records = (
        struct.pack("<BBHHH", 3, 0, 0, 2, 2),
        struct.pack("<BBHHH", 2, 0, 8, 2, 2),
        struct.pack("<BBHHH", 0x85, 0, 10, 2, 2),
        struct.pack("<BBHHH", 5, 4, 12, 2, 2),
        struct.pack("<BBHHH", 0, 4, 14, 2, 2),
        struct.pack("<BBHHH", 0, 0, 15, 2, 2),
        struct.pack("<BBHHH", 3, 4, 17, 2, 2),
        struct.pack("<BBHHH", 2, 4, 21, 2, 2),
    )

    obj = _load(_minimal_ne(first_segment_data=bytes(segment_data), relocation_records=records)).main_object

    assert len(obj.fixups) == 8
    assert obj.fixups[2].source_type == 5
    assert len(obj.relocs) == 9
    assert all(isinstance(relocation, NEInternalRelocation) for relocation in obj.relocs)
    assert all(relocation.resolved for relocation in obj.relocs)
    target = obj.segment_to_rva(2, 2)
    assert obj.memory.load(0, 8) == struct.pack("<II", target, target)
    assert obj.memory.load(8, 6) == struct.pack("<HHH", obj.segment_to_selector(2), 2, 5)
    assert obj.memory.load(14, 3) == b"\x01\x02\xff"
    assert obj.memory.load(17, 6) == struct.pack("<HHH", 1, obj.segment_to_selector(2), obj.segment_to_selector(2))


def test_can_leave_internal_fixups_unapplied():
    segment_data = struct.pack("<HH", 0xFFFF, 0)
    record = struct.pack("<BBHHH", 3, 0, 0, 2, 2)
    obj = _load(
        _minimal_ne(first_segment_data=segment_data, relocation_records=(record,)),
        perform_relocations=False,
    ).main_object

    assert obj.memory.load(0, 4) == segment_data
    assert len(obj.relocs) == 1
    assert obj.relocs[0].resolved


def test_rejects_nonzero_additive_selector_source():
    record = struct.pack("<BBHHH", 2, 4, 0, 2, 2)
    with pytest.raises(cle.CLEInvalidBinaryError, match="additive selector fixup.*nonzero addend"):
        _load(
            _minimal_ne(
                first_segment_data=struct.pack("<H", 1),
                relocation_records=(record,),
            )
        )


def test_resolves_imports_against_matching_ne_module(tmp_path):
    target_path = tmp_path / "lib.dll"
    target_path.write_bytes(_minimal_ne(module_name=b"LIB", is_dll=True, module_flags=4))
    segment_data = struct.pack("<HHHH", 0xFFFF, 0, 0xFFFF, 0)
    name_offset = 1 + len(b"LIB")
    records = (
        struct.pack("<BBHHH", 3, 2, 0, 1, name_offset),
        struct.pack("<BBHHH", 3, 1, 4, 1, 1),
    )
    main_data = _minimal_ne(
        with_import=True,
        first_segment_data=segment_data,
        relocation_records=records,
        import_module=b"LIB",
        import_name=b"Start",
    )
    main_path = tmp_path / "app.exe"
    main_path.write_bytes(main_data)

    loader = cle.Loader(
        str(main_path),
        auto_load_libs=True,
        ld_path=[tmp_path],
        case_insensitive=True,
    )
    obj = loader.main_object
    target = next(item for item in loader.all_objects if isinstance(item, cle.NE) and item is not obj)

    assert target.mapped_base % cle.NE.SEGMENT_SLOT_SIZE == 0
    assert target.provides == "lib.dll"
    assert target.execution_mode == "protected"
    assert len(obj.relocs) == 2
    assert all(relocation.resolvedby.owner is target for relocation in obj.relocs)
    assert obj.memory.load(0, 8) == struct.pack("<II", target.get_symbol("Start").rebased_addr, target.entry)


def test_expands_iterated_segment_data():
    compressed = struct.pack("<HH", 2, 2) + b"AB" + struct.pack("<HH", 1, 3) + b"XYZ"
    obj = _load(
        _minimal_ne(
            first_segment_data=compressed,
            first_segment_flags=0x08,
            first_segment_minimum=7,
        )
    ).main_object
    segment = obj.segments[0]

    assert segment.is_iterated
    assert segment.filesize == len(compressed)
    assert segment.initialized_size == 7
    assert segment.memsize == 7
    assert obj.memory.load(0, 7) == b"ABABXYZ"
    assert segment.addr_to_offset(0) is None
    assert segment.addr_to_offset(segment.max_addr + 1) is None
    assert segment.offset_to_addr(segment.offset) is None


@pytest.mark.parametrize(
    "compressed, message",
    [
        (struct.pack("<HH", 1, 3) + b"AB", "payload"),
        (struct.pack("<HH", 0xFFFF, 2) + b"AB", "exceeds 64 KiB"),
    ],
)
def test_rejects_invalid_iterated_segment_data(compressed, message):
    with pytest.raises(cle.CLEInvalidBinaryError, match=message):
        _load(
            _minimal_ne(
                first_segment_data=compressed,
                first_segment_flags=0x08,
                first_segment_minimum=7,
            )
        )


def test_rejects_cyclic_fixup_chain():
    with pytest.raises(cle.CLEInvalidBinaryError, match="Cycle in NE fixup chain"):
        _load(_minimal_ne(with_import=True, cyclic_fixup=True))


def test_rejects_out_of_bounds_segment_data():
    data = bytearray(_minimal_ne())
    struct.pack_into("<H", data, 0x80, 0xFFFF)
    with pytest.raises(cle.CLEInvalidBinaryError, match="Truncated NE segment 1 data"):
        _load(bytes(data))


def test_every_truncated_prefix_fails_closed():
    data = _minimal_ne(with_import=True)
    for length in range(len(data)):
        with pytest.raises((cle.CLECompatibilityError, cle.CLEInvalidBinaryError)):
            _load(data[:length])
