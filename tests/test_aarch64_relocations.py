#!/usr/bin/env python
from __future__ import annotations

import io
import os
import struct

import cle

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"))

R_AARCH64_NONE = 0
R_AARCH64_PREL32 = 261

# sizeof(Elf64_Rela)
RELA_ENTRY_SIZE = 0x18

# A section of four-byte fields, each covered by its own relocation against the undefined symbol
# "zero". Rewriting those relocations puts a PREL32 field at a chosen offset.
PREL32_SECTION = ".R_AARCH64_MOVW_SABS"


def test_aarch64_relocs():
    """
    Test some relocations on an AArch64 object file.
    :return:
    """
    path = os.path.join(test_location, "aarch64", "aarch64-relocs.o")
    loader = cle.Loader(path, main_opts={"base_addr": 0x210120}, auto_load_libs=True)
    relocations = loader.main_object.relocs
    aarch64_backend = cle.backends.elf.relocation.arm64

    expected_relocs = {
        0x210132: (aarch64_backend.R_AARCH64_ADR_PREL_PG_HI21, 0x90000001),
        0x21013B: (aarch64_backend.R_AARCH64_ADD_ABS_LO12_NC, 0x9104FC00),
        0x210144: (aarch64_backend.R_AARCH64_LDST64_ABS_LO12_NC, 0xF940A77C),
        0x210154: (aarch64_backend.R_AARCH64_CALL26, 0x97FFFFFF),
        0x210158: (aarch64_backend.R_AARCH64_JUMP26, 0x17FFFFFE),
        0x21015C: (aarch64_backend.R_AARCH64_LDST32_ABS_LO12_NC, 0xBD4160A4),
        0x210164: (aarch64_backend.R_AARCH64_LDST8_ABS_LO12_NC, 0x3985A1AB),
        0x21016C: (aarch64_backend.R_AARCH64_LDST128_ABS_LO12_NC, 0x3DC05E74),
        0x210174: (aarch64_backend.R_AARCH64_LDST16_ABS_LO12_NC, 0x7D430271),
        0x210178: (aarch64_backend.R_AARCH64_LDST16_ABS_LO12_NC, 0x79430261),
        0x21017C: (aarch64_backend.R_AARCH64_LDST16_ABS_LO12_NC, 0x79430662),
    }

    for r in relocations:
        if r.rebased_addr in expected_relocs:
            assert r.__class__ == expected_relocs[r.rebased_addr][0]
            assert r.owner.memory.unpack_word(r.relative_addr, size=4) == expected_relocs[r.rebased_addr][1]
            expected_relocs.pop(r.rebased_addr)

    assert not expected_relocs


def _load_with_prel32(prel32_offset):
    """
    Load aarch64-relocs.o with the relocations covering PREL32_SECTION rewritten: the field
    `prel32_offset` bytes into the section gets an R_AARCH64_PREL32 with a zero addend, and every
    other relocation becomes R_AARCH64_NONE so that it leaves its own field alone. A negative
    offset counts back from the end of the section, as in a slice.

    Returns the loader, a second loader over the same image that relocates nothing, and the
    address of the PREL32 field.
    """
    path = os.path.join(test_location, "aarch64", "aarch64-relocs.o")
    with open(path, "rb") as f:
        image = bytearray(f.read())

    probe = cle.Loader(path, main_opts={"base_addr": 0x210120}, auto_load_libs=False).main_object
    section = probe.sections_map[PREL32_SECTION]
    rela = probe.sections_map[".rela" + PREL32_SECTION]
    if prel32_offset < 0:
        prel32_offset += section.memsize

    for entry in range(rela.offset, rela.offset + rela.filesize, RELA_ENTRY_SIZE):
        r_offset, r_info = struct.unpack_from("<QQ", image, entry)
        symbol = r_info >> 32
        r_type = R_AARCH64_PREL32 if r_offset == prel32_offset else R_AARCH64_NONE
        struct.pack_into("<Qq", image, entry + 8, (symbol << 32) | r_type, 0)

    patched = bytes(image)
    loader = cle.Loader(io.BytesIO(patched), main_opts={"base_addr": 0x210120}, auto_load_libs=False)
    unrelocated = cle.Loader(
        io.BytesIO(patched), main_opts={"base_addr": 0x210120}, auto_load_libs=False, perform_relocations=False
    )
    return loader, unrelocated, section.vaddr + prel32_offset


def test_aarch64_prel32_at_section_end():
    """
    R_AARCH64_PREL32 covers a four-byte field, so one may sit in the last four bytes of a section.
    CLE used to store it with the generic architecture-word-sized write, which ran off the end of
    the section's backer and escaped the loader as a bare KeyError. Real aarch64 kernel modules hit
    this on the last __ksymtab entry.
    """
    loader, _, field = _load_with_prel32(-4)
    zero = loader.find_symbol("zero")
    assert zero is not None

    assert loader.memory.unpack_word(field, size=4) == (zero.rebased_addr - field) & 0xFFFFFFFF


def test_aarch64_prel32_leaves_the_next_field_alone():
    """
    The architecture-word-sized write also overwrote the four bytes following every relocated field.
    """
    loader, unrelocated, field = _load_with_prel32(0)
    zero = loader.find_symbol("zero")
    assert zero is not None

    assert loader.memory.unpack_word(field, size=4) == (zero.rebased_addr - field) & 0xFFFFFFFF
    assert loader.memory.load(field + 4, 4) == unrelocated.memory.load(field + 4, 4)


if __name__ == "__main__":
    test_aarch64_relocs()
    test_aarch64_prel32_at_section_end()
    test_aarch64_prel32_leaves_the_next_field_alone()
