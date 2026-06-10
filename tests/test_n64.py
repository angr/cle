from __future__ import annotations

import io
import os
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
FIXTURE = os.path.join(TEST_BASE, "tests", "mips", "n64", "test.z64")

ENTRY = 0x80040000
GAME_SIZE = 0x1000
BOOTCODE_VADDR = 0xA4000040
BOOTCODE_SIZE = 0xFC0


class TestN64Loader(unittest.TestCase):
    def test_loads_z64_rom(self):
        ld = cle.Loader(FIXTURE, auto_load_libs=False)
        obj = ld.main_object

        assert isinstance(obj, cle.N64)
        assert obj.os == "n64"
        assert obj.arch.name == "MIPS32"
        assert obj.arch.memory_endness == "Iend_BE"

        assert obj.entry == ENTRY
        assert obj.mapped_base == ENTRY
        assert obj.linked_base == ENTRY
        assert obj.min_addr == ENTRY

        # Header fields parsed correctly.
        assert obj.pi_register == 0x80371240
        assert obj.entry_pc == ENTRY
        assert obj.crc1 == 0xDEADBEEF
        assert obj.crc2 == 0xCAFEBABE
        assert obj.image_name == "CLE TEST ROM"
        assert obj.cartridge_id == b"NT"
        assert obj.country_code == b"E"
        assert obj.version == 0x00

        # Game code is mapped at the entry, and contains the MIPS instructions
        # we baked into the fixture: nop, jr $ra, nop, nop.
        assert obj.contains_addr(ENTRY)
        assert ld.memory.load(ENTRY, 16) == b"\x00\x00\x00\x00\x03\xe0\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"

        # Default loader maps the IPL3 bootcode as a second segment.
        assert obj.contains_addr(BOOTCODE_VADDR)
        assert ld.memory.load(BOOTCODE_VADDR, 4) == b"\xaa\xaa\xaa\xaa"
        assert obj.max_addr == BOOTCODE_VADDR + BOOTCODE_SIZE - 1

        # We should have two segments: game code + bootcode.
        seg_vaddrs = sorted(s.vaddr for s in obj.segments)
        assert seg_vaddrs == [ENTRY, BOOTCODE_VADDR]

    def test_skip_bootcode(self):
        ld = cle.Loader(
            FIXTURE,
            auto_load_libs=False,
            main_opts={"backend": "n64", "skip_bootcode": True},
        )
        obj = ld.main_object

        assert isinstance(obj, cle.N64)
        # Only the game-code segment should be present.
        assert len(obj.segments) == 1
        assert obj.segments[0].vaddr == ENTRY
        assert obj.max_addr == ENTRY + GAME_SIZE - 1
        # Bootcode address should not be backed by memory.
        assert not obj.contains_addr(BOOTCODE_VADDR)

    def test_is_compatible_detects_z64_magic(self):
        with open(FIXTURE, "rb") as f:
            assert cle.N64.is_compatible(f) is True

    def test_is_compatible_rejects_non_z64(self):
        # ELF magic should not be recognized as z64.
        assert cle.N64.is_compatible(io.BytesIO(b"\x7fELF" + b"\x00" * 100)) is False


if __name__ == "__main__":
    unittest.main()
