from __future__ import annotations

import io
import struct

import pytest

import cle


def _name_entry(name: bytes, ordinal: int) -> bytes:
    return bytes([len(name)]) + name + struct.pack("<H", ordinal)


def _minimal_ne(*, with_import: bool = False, cyclic_fixup: bool = False) -> bytes:
    ne_offset = 0x40
    segment_table = 0x40
    resource_table = 0x50
    resident_table = 0x54

    resident_names = _name_entry(b"SYNTH", 0) + _name_entry(b"Start", 1) + b"\0"
    module_table = resident_table + len(resident_names)
    imported_table = module_table + (2 if with_import else 0)
    imported_names = b"\x06KERNEL\x03FOO" if with_import else b""
    entry_table = imported_table + len(imported_names)
    entries = b"\x01\x01\x01\x00\x00\x00"  # one fixed entry in segment 1, followed by the terminator

    metadata_end = ne_offset + entry_table + len(entries)
    first_segment_offset = (metadata_end + 0x0F) & ~0x0F
    first_segment_data = b"\x02\x00\x00\x00" if cyclic_fixup else b"\x02\x00\xff\xff"
    if not with_import:
        first_segment_data = b"\x55\x8b\xec\xc3"
    relocation_table = (
        struct.pack("<HBBHHH", 1, 5, 2, 0, 1, 7) if with_import else b""
    )  # import KERNEL!FOO through the 0 -> 2 -> ffff source chain
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
    struct.pack_into("<H", header, 0x0C, 2)  # MULTIPLEDATA executable
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

    segment_flags = 0x100 if with_import else 0
    struct.pack_into(
        "<4H",
        result,
        ne_offset + segment_table,
        first_segment_offset >> 4,
        len(first_segment_data),
        segment_flags,
        len(first_segment_data),
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


def _load(data: bytes) -> cle.Loader:
    return cle.Loader(io.BytesIO(data), auto_load_libs=False)


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


def test_expands_import_fixup_chains_without_fabricating_extern_addresses():
    loader = _load(_minimal_ne(with_import=True))
    obj = loader.main_object

    assert isinstance(obj, cle.NE)
    assert obj.imported_modules == ("kernel",)
    assert obj.deps == ["kernel"]
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
    assert all(not relocation.resolved for relocation in obj.relocs)
    assert len(loader.all_objects) == 1
    assert obj.memory.load(0, 4) == b"\x02\x00\xff\xff"


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
