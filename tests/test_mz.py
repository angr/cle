from __future__ import annotations

import io
import struct

import pytest

import cle
from cle.backends.mz import MZRelocation


def _minimal_mz(
    *,
    image: bytes | None = None,
    relocations: tuple[tuple[int, int], ...] = ((4, 0),),
    header_size: int = 0x40,
    relocation_offset: int = 0x1C,
    minimum_extra_paragraphs: int = 4,
    maximum_extra_paragraphs: int = 0xFFFF,
    initial_ss: int = 4,
    initial_sp: int = 0x10,
    initial_cs: int = 1,
    initial_ip: int = 2,
    overlay_number: int = 0,
    extension: tuple[int, bytes] | None = None,
    trailing: bytes = b"",
) -> bytes:
    if image is None:
        mutable_image = bytearray(range(0x40))
        struct.pack_into("<H", mutable_image, 4, 0x20)
    else:
        mutable_image = bytearray(image)

    if extension is not None:
        extension_offset, signature = extension
        required_image_size = extension_offset + len(signature) - header_size
        if required_image_size > len(mutable_image):
            mutable_image.extend(b"\0" * (required_image_size - len(mutable_image)))

    declared_file_size = header_size + len(mutable_image)
    pages_in_file = (declared_file_size + 511) // 512
    bytes_in_last_page = declared_file_size % 512
    result = bytearray(declared_file_size)
    struct.pack_into(
        "<14H",
        result,
        0,
        0x5A4D,
        bytes_in_last_page,
        pages_in_file,
        len(relocations),
        header_size // 16,
        minimum_extra_paragraphs,
        maximum_extra_paragraphs,
        initial_ss,
        initial_sp,
        0,
        initial_ip,
        initial_cs,
        relocation_offset,
        overlay_number,
    )
    for index, (offset, segment) in enumerate(relocations):
        struct.pack_into("<HH", result, relocation_offset + index * 4, offset, segment)
    result[header_size:] = mutable_image

    if extension is not None:
        extension_offset, signature = extension
        struct.pack_into("<I", result, 0x3C, extension_offset)
        result[extension_offset : extension_offset + len(signature)] = signature

    return bytes(result) + trailing


def _load(data: bytes, **kwargs) -> cle.Loader:
    return cle.Loader(io.BytesIO(data), auto_load_libs=False, **kwargs)


def _replace_word(data: bytes, offset: int, value: int) -> bytes:
    result = bytearray(data)
    struct.pack_into("<H", result, offset, value)
    return bytes(result)


def test_loads_mz_image_entry_stack_and_public_backend():
    data = _minimal_mz(trailing=b"overlay bytes are not part of the declared image")
    stream = io.BytesIO(data)
    stream.seek(7)
    assert cle.MZ.is_compatible(stream)
    assert stream.tell() == 7
    assert cle.ALL_BACKENDS["mz"] is cle.MZ

    obj = _load(data).main_object

    assert isinstance(obj, cle.MZ)
    assert obj.arch.name == "x86:LE:16:Real Mode"
    assert obj.arch.bits == 16
    assert obj.mapped_address_bits == 20
    assert obj.address_model == "dos-mz-linear20-v1"
    assert obj.os == "dos"
    assert obj.entry == 0x12
    assert obj.initial_stack == 0x50
    assert obj.initial_cs_value == 1
    assert obj.initial_ss_value == 4
    assert obj.cached_content is None

    assert obj.mz_header.header_size == 0x40
    assert obj.mz_header.image_size == 0x40
    assert obj.mz_header.minimum_allocation_size == 0x80
    assert obj.declared_file_size == 0x80
    assert obj.trailing_size == len(b"overlay bytes are not part of the declared image")
    assert obj.max_addr == 0x7F

    assert len(obj.segments) == 1
    segment = obj.segments[0]
    assert segment.offset == 0x40
    assert segment.vaddr == 0
    assert segment.filesize == 0x40
    assert segment.memsize == 0x80
    assert obj.memory.load(0, 8) == data[0x40:0x48]
    assert obj.addr_to_offset(0) == 0x40
    assert obj.offset_to_addr(0x40) == 0

    assert len(obj.relocs) == 1
    relocation = obj.relocs[0]
    assert isinstance(relocation, MZRelocation)
    assert relocation.resolved
    assert (relocation.segment, relocation.offset, relocation.relative_addr) == (0, 4, 4)
    assert obj.memory.unpack_word(4, size=2) == 0x20


def test_applies_load_segment_relocations_and_can_disable_them():
    image = bytearray(range(0x40))
    struct.pack_into("<H", image, 4, 0xF000)
    data = _minimal_mz(image=bytes(image))
    base = 0x12340
    opts = {"backend": "mz", "base_addr": base, "force_rebase": True}

    loader = _load(data, main_opts=opts)
    obj = loader.main_object
    assert obj.mapped_base == base
    assert obj.load_segment == 0x1234
    assert obj.entry == base + 0x12
    assert obj.initial_stack == base + 0x50
    assert obj.initial_cs_value == 0x1235
    assert obj.initial_ss_value == 0x1238
    assert obj.memory.unpack_word(4, size=2) == 0x0234
    assert loader.memory.unpack_word(base + 4, size=2) == 0x0234

    unrelocated = _load(data, main_opts=opts, perform_relocations=False).main_object
    assert unrelocated.memory.unpack_word(4, size=2) == 0xF000
    assert len(unrelocated.relocs) == 1
    assert unrelocated.relocs[0].resolved


def test_rejects_unrepresentable_load_bases():
    data = _minimal_mz()
    with pytest.raises(cle.CLEOperationError, match="20-bit"):
        _load(
            data,
            main_opts={"backend": "mz", "base_addr": -0x10, "force_rebase": True},
        )
    with pytest.raises(cle.CLEOperationError, match="paragraph-aligned"):
        _load(
            data,
            main_opts={"backend": "mz", "base_addr": 0x12345, "force_rebase": True},
        )
    with pytest.raises(cle.CLEOperationError, match="20-bit"):
        _load(
            data,
            main_opts={"backend": "mz", "base_addr": 0xFFFC0, "force_rebase": True},
        )


@pytest.mark.parametrize(
    ("data", "message"),
    (
        (b"MZ", "fixed header"),
        (b"ZZ" + _minimal_mz()[2:], "signature"),
        (_replace_word(_minimal_mz(), 4, 0), "zero file pages"),
        (_replace_word(_minimal_mz(), 2, 512), "final-page byte count"),
        (_replace_word(_minimal_mz(), 4, 2), "Truncated MZ image"),
        (_replace_word(_minimal_mz(), 8, 1), "header size"),
        (_replace_word(_minimal_mz(), 8, 0x100), "header size"),
        (
            _minimal_mz(relocation_offset=0x1A),
            "relocation table overlaps",
        ),
        (
            _minimal_mz(relocation_offset=0x3E),
            "relocation table extends",
        ),
        (
            _minimal_mz(relocations=((0xFFFF, 0xFFFF),)),
            "relocation 0 target",
        ),
        (
            _minimal_mz(initial_cs=4, initial_ip=0),
            "entry point",
        ),
        (
            _minimal_mz(minimum_extra_paragraphs=0xFFFF),
            "minimum allocation exceeds the 20-bit",
        ),
        (
            _minimal_mz(initial_ss=8, initial_sp=1),
            "initial stack",
        ),
        (
            _minimal_mz(overlay_number=1),
            "not an ordinary primary executable",
        ),
    ),
)
def test_rejects_malformed_or_unsupported_mz(data, message):
    stream = io.BytesIO(data)
    stream.seek(min(3, len(data)))
    original = stream.tell()
    assert not cle.MZ.is_compatible(stream)
    assert stream.tell() == original

    with pytest.raises(cle.CLEInvalidBinaryError, match=message):
        _load(data, main_opts={"backend": "mz"})


@pytest.mark.parametrize("signature", (b"PE\0\0", b"NE", b"LE", b"LX", b"W3", b"W4"))
def test_does_not_claim_recognized_extended_mz_containers(signature):
    data = _minimal_mz(extension=(0x80, signature))
    assert not cle.MZ.is_compatible(io.BytesIO(data))
    with pytest.raises(cle.CLEInvalidBinaryError, match="extended"):
        _load(data, main_opts={"backend": "mz"})


def test_does_not_interpret_pre_dos4_image_bytes_as_an_extension_pointer():
    data = _minimal_mz(
        header_size=0x20,
        relocations=(),
        extension=(0x60, b"NE"),
    )
    assert cle.MZ.is_compatible(io.BytesIO(data))
    assert isinstance(_load(data).main_object, cle.MZ)


def test_minimum_allocation_remains_authoritative_when_maximum_is_smaller():
    obj = _load(
        _minimal_mz(
            minimum_extra_paragraphs=4,
            maximum_extra_paragraphs=1,
        )
    ).main_object

    assert obj.minimum_extra_paragraphs == 4
    assert obj.maximum_extra_paragraphs == 1
    assert obj.mz_header.minimum_allocation_size == 0x80


def test_full_final_page_and_unused_relocation_offset_follow_dos_semantics():
    data = _minimal_mz(
        image=b"\x90" * 0x1C0,
        relocations=(),
        relocation_offset=0xFFFF,
        initial_ss=0x1C,
        initial_sp=0,
    )
    obj = _load(data).main_object

    assert obj.mz_header.bytes_in_last_page == 0
    assert obj.declared_file_size == 0x200
    assert obj.mz_header.image_size == 0x1C0
    assert obj.initial_stack == 0x1C0
    assert obj.relocs == []


class _BoundedStream(io.BytesIO):
    def __init__(self, data: bytes, maximum_read: int):
        super().__init__(data)
        self.maximum_read = maximum_read
        self.largest_read = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0 or size > self.maximum_read:
            raise AssertionError(f"unbounded read of {size} bytes")
        self.largest_read = max(self.largest_read, size)
        return super().read(size)


def test_loader_reads_only_declared_bounded_ranges():
    data = _minimal_mz(trailing=b"x" * 0x10000)
    stream = _BoundedStream(data, 0x40)
    obj = cle.MZ(None, stream, is_main_bin=True)

    assert obj.trailing_size == 0x10000
    assert stream.largest_read == 0x40
