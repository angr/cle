from __future__ import annotations

import os
from io import BytesIO

import cle

tests_path = os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests")


def test_patched_stream():
    stream = BytesIO(b"0123456789abcdef")

    stream1 = cle.PatchedStream(stream, [(2, b"AA")])
    stream1.seek(0)
    assert stream1.read() == b"01AA456789abcdef"

    stream2 = cle.PatchedStream(stream, [(2, b"AA")])
    stream2.seek(0)
    assert stream2.read(3) == b"01A"

    stream3 = cle.PatchedStream(stream, [(2, b"AA")])
    stream3.seek(3)
    assert stream3.read(3) == b"A45"

    stream4 = cle.PatchedStream(stream, [(-1, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")])
    stream4.seek(0)
    assert stream4.read() == b"A" * 0x10


def assert_image_matches_file(ld, path):
    """The loaded image must hold the file's own bytes, not the fields CLE zeroed to reread it."""
    with open(path, "rb") as f:
        image = f.read()
    segment = ld.main_object.segments[0]
    loaded = ld.memory.load(segment.vaddr, segment.filesize)
    assert loaded == image[segment.offset : segment.offset + segment.filesize]


def test_malformed_sections():
    path = os.path.join(tests_path, "i386", "oxfoo1m3")
    ld = cle.Loader(path, auto_load_libs=True)
    assert len(ld.main_object.segments) == 1
    assert len(ld.main_object.sections) == 0

    # This one maps its ELF header, so the fields have somewhere to go back to.
    assert ld.main_object.offset_to_addr(0) is not None
    assert_image_matches_file(ld, path)


def test_malformed_sections_unmapped_header():
    # bios.bin.truncated.elf is bios.bin.elf cut at the end of its only PT_LOAD, so the section
    # header table is gone and pyelftools cannot walk it. That segment starts at file offset 0x70,
    # so the ELF header is mapped nowhere and none of the zeroed fields has an address at all.
    path = os.path.join(tests_path, "i386", "bios.bin.truncated.elf")
    ld = cle.Loader(path, auto_load_libs=False)
    assert len(ld.main_object.segments) == 1
    assert len(ld.main_object.sections) == 0

    assert ld.main_object.offset_to_addr(0) is None
    assert_image_matches_file(ld, path)
