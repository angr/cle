#!/usr/bin/env python
from __future__ import annotations

import os

import cle


def test_aarch64_relocs():
    """
    Test some relocations on an AArch64 object file.
    :return:
    """
    test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"))
    path = os.path.join(test_location, "aarch64", "aarch64-relocs.o")
    loader = cle.Loader(path, main_opts={"base_addr": 0x210120})
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


if __name__ == "__main__":
    test_aarch64_relocs()
