from __future__ import annotations

import io
import os
import struct

import cle
from cle.backends.cgc.cgc import CGC_HEADER, ELF_HEADER

TESTS_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
CGC_PATH = os.path.join(TESTS_PATH, "cgc", "CADET_00002")

# Real CGC challenge binaries put their first PT_LOAD well past the 16-byte header. 8 leaves the header
# straddling the segment boundary, which no shipped binary does but the backend still has to get right.
UNMAPPED_OFFSET = 0xA0
PARTIAL_OFFSET = 8


def start_first_load_at(data: bytes, offset: int) -> bytes:
    """
    Rewrite the first PT_LOAD of a CGC binary to start at ``offset`` instead of file offset 0, leaving the
    bytes it maps at the virtual addresses they had before.
    """
    patched = bytearray(data)
    (e_phoff,) = struct.unpack_from("<I", patched, 0x1C)
    e_phentsize, e_phnum = struct.unpack_from("<HH", patched, 0x2A)
    assert e_phentsize == 32, "CGC binaries are 32-bit ELF"
    for i in range(e_phnum):
        entry = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
            "<8I", patched, entry
        )
        if p_type == 1 and p_offset == 0:  # PT_LOAD
            struct.pack_into(
                "<8I",
                patched,
                entry,
                p_type,
                p_offset + offset,
                p_vaddr + offset,
                p_paddr + offset,
                p_filesz - offset,
                p_memsz - offset,
                p_flags,
                p_align,
            )
            return bytes(patched)
    raise AssertionError("no PT_LOAD at file offset 0")


def read_cgc() -> bytes:
    with open(CGC_PATH, "rb") as f:
        return f.read()


def test_cgc_mapped_header():
    ld = cle.Loader(CGC_PATH, auto_load_libs=False)
    obj = ld.main_object
    assert isinstance(obj, cle.backends.CGC)

    # The ELF magic the backend substitutes into the stream is replaced by the real CGC header in memory.
    assert ld.memory.load(obj.offset_to_addr(0), len(CGC_HEADER)) == CGC_HEADER


def test_cgc_unmapped_header():
    original = read_cgc()
    ld = cle.Loader(io.BytesIO(start_first_load_at(original, UNMAPPED_OFFSET)), auto_load_libs=False)
    obj = ld.main_object
    assert isinstance(obj, cle.backends.CGC)

    # Nothing maps the header, so none of the substituted ELF magic reaches memory.
    assert obj.offset_to_addr(0) is None
    assert not any(ELF_HEADER[:4] in bytes(backer) for _, backer in obj.memory.backers())

    (entry,) = struct.unpack_from("<I", original, 0x18)
    assert obj.entry == entry
    load_addr = obj.offset_to_addr(UNMAPPED_OFFSET)
    assert ld.memory.load(load_addr, 16) == original[UNMAPPED_OFFSET : UNMAPPED_OFFSET + 16]


def test_cgc_partially_mapped_header():
    ld = cle.Loader(io.BytesIO(start_first_load_at(read_cgc(), PARTIAL_OFFSET)), auto_load_libs=False)
    obj = ld.main_object
    assert isinstance(obj, cle.backends.CGC)

    # Only the tail of the header is mapped, and that is exactly the part that gets repaired.
    assert obj.offset_to_addr(0) is None
    tail_addr = obj.offset_to_addr(PARTIAL_OFFSET)
    assert ld.memory.load(tail_addr, len(CGC_HEADER) - PARTIAL_OFFSET) == CGC_HEADER[PARTIAL_OFFSET:]


if __name__ == "__main__":
    test_cgc_mapped_header()
    test_cgc_unmapped_header()
    test_cgc_partially_mapped_header()
