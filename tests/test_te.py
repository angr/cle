from __future__ import annotations

import io

import cle
from cle.backends.te import HEADER, SECTION_HEADER


def test_section_permissions():
    header = HEADER.pack(
        0x5A56,
        0x014C,
        2,
        10,
        HEADER.size,
        0x100,
        0x100,
        0x400000,
        0,
        0,
        0,
        0,
    )
    text_offset = HEADER.size + 2 * SECTION_HEADER.size
    text_header = SECTION_HEADER.pack(
        b".text\0\0\0",
        1,
        0x100,
        1,
        text_offset,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data_header = SECTION_HEADER.pack(
        b".data\0\0\0",
        1,
        0x200,
        1,
        text_offset + 1,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    loader = cle.Loader(
        io.BytesIO(header + text_header + data_header + b"\xc3\0"),
        auto_load_libs=False,
        main_opts={"backend": "te"},
    )
    assert loader.main_object.entry == 0x400100

    sections = {section.name: section for section in loader.main_object.sections}

    text = sections[".text"]
    assert text.is_readable
    assert not text.is_writable
    assert text.is_executable
    assert not text.only_contains_uninitialized_data

    data = sections[".data"]
    assert data.is_readable
    assert data.is_writable
    assert not data.is_executable
    assert not data.only_contains_uninitialized_data
