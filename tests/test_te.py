"""Tests for the Terse Executable backend.

TE images are PE images with the DOS and PE headers replaced by a 40-byte TE header. The section table is copied
verbatim, so its addresses and file offsets still describe the *original* PE file: an image that stripped
``stripped_size`` bytes of headers has every recorded file offset sitting ``stripped_size - sizeof(TE header)`` bytes
further along than the byte actually is in the TE file. These tests build TE images by hand rather than shipping a
firmware fixture, because that header arithmetic is exactly what is being checked.
"""

from __future__ import annotations

import io

import cle
from cle.backends.coff import IMAGE_SCN
from cle.backends.te import HEADER, SECTION_HEADER, HeaderType, SectionHeaderType

TE_SIGNATURE = 0x5A56  # b"VZ"
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
EFI_APPLICATION = 10

# a realistic amount of stripped PE header. Keeping this larger than HEADER.size is what makes the tests notice a
# backend that forgets the strip adjustment; with the two equal, every address happens to come out right anyway.
STRIPPED_SIZE = 0x100


def build_te(machine, image_base, entry_rva, sections, stripped_size=STRIPPED_SIZE):
    """
    Assemble a TE image.

    :param sections:    ``(name, virtual_address, virtual_size, characteristics, raw_data)`` tuples, laid out in the
                        file in the order given.
    :return:            A stream the loader can consume.
    """
    # file offsets recorded in the section table are offsets into the pre-strip PE file
    stripped_offset = stripped_size - HEADER.size
    body_offset = HEADER.size + len(sections) * SECTION_HEADER.size

    section_headers = b""
    body = b""
    for name, virtual_address, virtual_size, characteristics, raw_data in sections:
        section_headers += SECTION_HEADER.pack(
            *SectionHeaderType(
                section_name=name.encode().ljust(8, b"\0"),
                physical_address_virtual_size=virtual_size,
                virtual_address=virtual_address,
                size_of_raw_data=len(raw_data),
                pointer_to_raw_data=body_offset + len(body) + stripped_offset,
                pointer_to_relocations=0,
                pointer_to_line_numbers=0,
                number_of_relocations=0,
                number_of_line_numbers=0,
                characteristics=characteristics,
            )
        )
        body += raw_data

    header = HEADER.pack(
        *HeaderType(
            signature=TE_SIGNATURE,
            machine=machine,
            number_of_sections=len(sections),
            subsystem=EFI_APPLICATION,
            stripped_size=stripped_size,
            address_of_entry_point=entry_rva,
            base_of_code=sections[0][1] if sections else 0,
            image_base=image_base,
            data_directory_0_virtual_address=0,
            data_directory_0_size=0,
            data_directory_1_virtual_address=0,
            data_directory_1_size=0,
        )
    )
    return io.BytesIO(header + section_headers + body)


def load_te(stream):
    return cle.Loader(stream, auto_load_libs=False, main_opts={"backend": "te"})


def sections_by_name(obj):
    return {section.name: section for section in obj.sections}


def test_entry_point():
    code = bytes(range(0x10))
    stream = build_te(
        IMAGE_FILE_MACHINE_I386,
        image_base=0x400000,
        entry_rva=0x1004,
        sections=[(".text", 0x1000, len(code), IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_EXECUTE, code)],
    )
    obj = load_te(stream).main_object

    # the whole image sits at image_base + (stripped_size - sizeof(TE header)), so the entry RVA lands there too
    expected = 0x400000 + STRIPPED_SIZE - HEADER.size + 0x1004
    assert obj.entry == expected

    # the entry point must agree with where the sections were actually mapped, not just with some fixed formula
    text = sections_by_name(obj)[".text"]
    assert text.contains_addr(obj.entry)
    assert obj.loader.memory.load(obj.entry, 4) == code[4:8]


def test_section_permissions():
    stream = build_te(
        IMAGE_FILE_MACHINE_I386,
        image_base=0x400000,
        entry_rva=0x1000,
        sections=[
            (".text", 0x1000, 4, IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_EXECUTE, b"\xc3\x00\x00\x00"),
            (".data", 0x2000, 4, IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_WRITE, b"\x01\x02\x03\x04"),
            (".bss", 0x3000, 0x20, IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_WRITE | IMAGE_SCN.CNT_UNINITIALIZED_DATA, b""),
        ],
    )
    obj = load_te(stream).main_object
    sections = sections_by_name(obj)

    # angr builds its permission map by walking every object's segments, which is the query that used to raise
    assert [(s.is_readable, s.is_writable, s.is_executable) for s in obj.segments] == [
        (True, False, True),
        (True, True, False),
        (True, True, False),
    ]

    text = sections[".text"]
    assert (text.is_readable, text.is_writable, text.is_executable) == (True, False, True)
    assert not text.only_contains_uninitialized_data

    data = sections[".data"]
    assert (data.is_readable, data.is_writable, data.is_executable) == (True, True, False)
    assert not data.only_contains_uninitialized_data

    bss = sections[".bss"]
    assert (bss.is_readable, bss.is_writable, bss.is_executable) == (True, True, False)
    assert bss.only_contains_uninitialized_data
    # .bss occupies memory but no file bytes; the base class would have reported filesize == memsize
    assert (bss.filesize, bss.memsize) == (0, 0x20)


def test_section_file_offsets():
    code = bytes(range(0x10))
    stream = build_te(
        IMAGE_FILE_MACHINE_I386,
        image_base=0x400000,
        entry_rva=0x1004,
        sections=[(".text", 0x1000, len(code), IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_EXECUTE, code)],
    )
    image = stream.getvalue()
    obj = load_te(stream).main_object

    # a section offset has to index the TE file cle was handed, not the PE file the section table was copied from
    text = sections_by_name(obj)[".text"]
    assert image[text.offset : text.offset + text.filesize] == code
    assert obj.addr_to_offset(obj.entry) == text.offset + 4


def test_partially_backed_section():
    initialized = b"\xaa" * 0x10
    stream = build_te(
        IMAGE_FILE_MACHINE_I386,
        image_base=0x400000,
        entry_rva=0x1000,
        sections=[(".data", 0x1000, 0x18, IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_WRITE, initialized)],
    )
    obj = load_te(stream).main_object

    data = sections_by_name(obj)[".data"]
    assert (data.filesize, data.memsize) == (0x10, 0x18)
    # the bytes past the raw data still belong to the section, so they have to be mapped and zeroed
    assert obj.loader.memory.load(data.vaddr, data.memsize) == initialized + b"\0" * 8


def test_aarch64_machine():
    code = b"\xc0\x03\x5f\xd6"  # ret
    stream = build_te(
        IMAGE_FILE_MACHINE_ARM64,
        image_base=0x400000,
        entry_rva=0x1000,
        sections=[(".text", 0x1000, len(code), IMAGE_SCN.MEM_READ | IMAGE_SCN.MEM_EXECUTE, code)],
    )
    obj = load_te(stream).main_object

    assert obj.arch.name == "AARCH64"
    assert obj.loader.memory.load(obj.entry, len(code)) == code


if __name__ == "__main__":
    test_entry_point()
    test_section_permissions()
    test_section_file_offsets()
    test_partially_backed_section()
    test_aarch64_machine()
