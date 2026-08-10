"""
Tests for the Terse Executable backend.

TE images are PE images with the DOS and PE headers replaced by a 40-byte TE header. The section table is copied
verbatim, so every file offset it records still describes the original PE file.
"""

from __future__ import annotations

import os

import cle
from cle.backends.te import HEADER

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

# what tests_src/te/build_te_images.py assembles: .text with the entry point 4 bytes into it, .data whose virtual
# size runs 8 bytes past its raw data, and .bss with no raw data at all
IMAGE_BASE = 0x400000
STRIPPED_SIZE = 0x100
ENTRY_RVA = 0x1004
# the image sits stripped_size - sizeof(TE header) above image_base, and RVAs are relative to that
ENTRY = IMAGE_BASE + STRIPPED_SIZE - HEADER.size + ENTRY_RVA


def load_te(arch):
    path = os.path.join(TEST_BASE, "tests", arch, "te_sections.te")
    return cle.Loader(path, auto_load_libs=False, main_opts={"backend": "te"}).main_object


def sections_by_name(obj):
    return {section.name: section for section in obj.sections}


def test_entry_point():
    obj = load_te("i386")
    assert obj.entry == ENTRY

    # the entry point must agree with where the sections were actually mapped, not just with a fixed formula
    text = sections_by_name(obj)[".text"]
    assert text.contains_addr(obj.entry)
    assert obj.loader.memory.load(obj.entry, 3) == b"\x31\xc0\xc3"  # xor eax, eax; ret


def test_section_permissions():
    obj = load_te("i386")
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
    obj = load_te("i386")
    with open(obj.binary, "rb") as f:
        image = f.read()

    # a section offset has to index the TE file cle was handed, not the PE file the section table was copied from
    text = sections_by_name(obj)[".text"]
    assert image[text.offset : text.offset + text.filesize] == obj.loader.memory.load(text.vaddr, text.filesize)
    assert obj.addr_to_offset(obj.entry) == text.offset + 4


def test_partially_backed_section():
    obj = load_te("i386")

    data = sections_by_name(obj)[".data"]
    assert (data.filesize, data.memsize) == (0x10, 0x18)
    # the bytes past the raw data still belong to the section, so they have to be mapped and zeroed
    assert obj.loader.memory.load(data.vaddr, data.memsize) == b"\xaa" * 0x10 + b"\0" * 8


def test_aarch64_machine():
    obj = load_te("aarch64")

    assert obj.arch.name == "AARCH64"
    assert obj.loader.memory.load(obj.entry, 8) == b"\x00\x00\x80\x52\xc0\x03\x5f\xd6"  # mov w0, #0; ret


if __name__ == "__main__":
    test_entry_point()
    test_section_permissions()
    test_section_file_offsets()
    test_partially_backed_section()
    test_aarch64_machine()
