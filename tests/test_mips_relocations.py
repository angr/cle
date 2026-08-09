# pylint: disable=missing-class-docstring
from __future__ import annotations

import binascii
import io
import os
import struct
import unittest

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import cle

TEST_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
    os.path.join("mips", "mips-hilo.o"),
)

BASE_ADDR = 0x21000

# 0x21000:        R_MIPS_HI16     3c080002        lui     $t0, 2
# 0x21004:        R_MIPS_HI16     3c090002        lui     $t1, 2
# 0x21008:        R_MIPS_LO16     21081004        addi    $t0, $t0, 4100
# 0x2100c:        R_MIPS_LO16     2108102c        addi    $t0, $t0, 4140
# 0x21010:        R_MIPS_HI16     3c080003        lui     $t0, 3
# 0x21014:        R_MIPS_HI16     3c090004        lui     $t1, 4
# 0x21018:        R_MIPS_LO16     2108101c        addi    $t0, $t0, 4124
EXPECTED_RESULT = b"3c0800023c090002210810042108102c3c0800033c0900042108101c"

# The (lui, addi) offsets of the listing above: an R_MIPS_HI16 site paired with the
# R_MIPS_LO16 site whose sign-extended immediate the instruction adds to it.
HILO_PAIRS = ((0x00, 0x08), (0x04, 0x0C), (0x10, 0x18), (0x14, 0x18))

R_MIPS_HI16 = 5
R_MIPS_LO16 = 6

SHT_RELA = 4
REL_ENTSIZE = 8
RELA_FORMAT = ">III"

# Offsets of the Elf32_Shdr fields this file rewrites.
SH_TYPE = 4
SH_OFFSET = 16
SH_SIZE = 20
SH_ENTSIZE = 36


def _computed_address(image, hi_offset, lo_offset):
    """
    The 32-bit address the lui/addi pair at these offsets builds at run time.
    """
    hi = struct.unpack_from(">H", image, hi_offset + 2)[0]
    lo = struct.unpack_from(">H", image, lo_offset + 2)[0]
    return ((hi << 16) + (lo - 0x10000 if lo & 0x8000 else lo)) & 0xFFFFFFFF


class _Fixture:
    """
    The pieces of the test file the variants below are built out of: its bytes, the section
    header offsets they patch, and the SHT_REL entries with the immediate each one relocates.
    """

    def __init__(self):
        with open(TEST_FILE, "rb") as stream:
            self.data = bytearray(stream.read())
            stream.seek(0)
            elf = ELFFile(stream)
            shoff = elf.header["e_shoff"]
            shentsize = elf.header["e_shentsize"]
            self.reloc_shdr = shoff + elf.get_section_index(".rel.text") * shentsize
            text_section = elf.get_section_by_name(".text")
            reloc_section = elf.get_section_by_name(".rel.text")
            assert text_section is not None
            assert isinstance(reloc_section, RelocationSection)
            self.text_offset = text_section.header["sh_offset"]
            self.reloc_size = reloc_section.header["sh_size"]
            text = text_section.data()
            self.relocs = [
                (
                    reloc.entry.r_offset,
                    reloc.entry.r_info_sym,
                    reloc.entry.r_info_type,
                    struct.unpack_from(">H", text, reloc.entry.r_offset + 2)[0],
                )
                for reloc in reloc_section.iter_relocations()
            ]

    def addends(self):
        """
        The AHL addend of every entry, computed the way a SHT_REL consumer does: AHI comes out
        of the R_MIPS_HI16 instruction and the signed ALO out of the R_MIPS_LO16 it pairs with.
        """
        addends = {}
        for index, (_, sym, reloc_type, ahi) in enumerate(self.relocs):
            if reloc_type != R_MIPS_HI16:
                continue
            partner = next(
                other
                for other in range(index, len(self.relocs))
                if self.relocs[other][1] == sym and self.relocs[other][2] == R_MIPS_LO16
            )
            alo = self.relocs[partner][3]
            addends[index] = addends[partner] = (ahi << 16) + (alo - 0x10000 if alo & 0x8000 else alo)
        assert len(addends) == len(self.relocs)
        return addends


def _rela_variant(shift=0):
    """
    Rewrite the test file as a MIPS64 or n32 producer emits the same code: SHT_RELA entries
    carrying the whole addend in r_addend, with the instruction immediates cleared. The entries
    are then reversed, which puts every R_MIPS_HI16 behind the R_MIPS_LO16 it pairs with. Real
    objects reach that arrangement one relocation at a time, usually for a `lui` in the delay
    slot of a backward branch; reversing the table puts every pair in it at once.
    With no shift, relocating it has to produce the same bytes as the SHT_REL original;
    `shift` moves every address the file computes by that much.

    The section keeps its `.rel.text` name, since sh_type and sh_entsize are what pyelftools
    and CLE read.
    """
    fixture = _Fixture()
    addends = fixture.addends()

    for r_offset, _, _, _ in fixture.relocs:
        struct.pack_into(">H", fixture.data, fixture.text_offset + r_offset + 2, 0)

    entries = b"".join(
        struct.pack(RELA_FORMAT, r_offset, (sym << 8) | reloc_type, addends[index] + shift)
        for index, (r_offset, sym, reloc_type, _) in reversed(list(enumerate(fixture.relocs)))
    )

    # The section header table sits at the end of the file, so the wider entries go past it.
    struct.pack_into(">I", fixture.data, fixture.reloc_shdr + SH_TYPE, SHT_RELA)
    struct.pack_into(">I", fixture.data, fixture.reloc_shdr + SH_OFFSET, len(fixture.data))
    struct.pack_into(">I", fixture.data, fixture.reloc_shdr + SH_SIZE, len(entries))
    struct.pack_into(">I", fixture.data, fixture.reloc_shdr + SH_ENTSIZE, struct.calcsize(RELA_FORMAT))
    fixture.data += entries

    return io.BytesIO(fixture.data)


def _unpaired_variant():
    """
    Shorten the section by one Elf32_Rel entry to drop the trailing R_MIPS_LO16, leaving the
    two R_MIPS_HI16 relocations against the .data section symbol without a partner.
    """
    fixture = _Fixture()
    struct.pack_into(">I", fixture.data, fixture.reloc_shdr + SH_SIZE, fixture.reloc_size - REL_ENTSIZE)
    return io.BytesIO(fixture.data)


class TestMipsRellocations(unittest.TestCase):

    @staticmethod
    def test_mips_hilo16():
        ld = cle.Loader(TEST_FILE, auto_load_libs=False, main_opts={"base_addr": BASE_ADDR})
        assert EXPECTED_RESULT == binascii.hexlify(ld.memory.load(BASE_ADDR, 0x1C))

    @staticmethod
    def test_mips_hilo16_rela():
        ld = cle.Loader(_rela_variant(), auto_load_libs=False, main_opts={"base_addr": BASE_ADDR})
        assert EXPECTED_RESULT == binascii.hexlify(ld.memory.load(BASE_ADDR, 0x1C))

    @staticmethod
    def test_mips_hilo16_rela_lo16_carry():
        # Addends big enough that every low halfword comes out negative once sign-extended, so
        # each R_MIPS_HI16 has to load one more than the plain high half to compensate.
        shift = 0x7001
        ld = cle.Loader(_rela_variant(shift=shift), auto_load_libs=False, main_opts={"base_addr": BASE_ADDR})
        image = ld.memory.load(BASE_ADDR, 0x1C)

        unshifted = binascii.unhexlify(EXPECTED_RESULT)
        for hi_offset, lo_offset in HILO_PAIRS:
            address = _computed_address(image, hi_offset, lo_offset)
            assert address & 0x8000, "the shift no longer reaches the carry this test is about"
            assert address == _computed_address(unshifted, hi_offset, lo_offset) + shift

    def test_mips_hi16_without_lo16(self):
        # The two R_MIPS_HI16 that lost their partner keep the immediates the file came with.
        expected = b"3c0800023c090002210810042108102c3c0800013c0900022108fffc"
        with self.assertLogs("cle.backends.elf.relocation.mips", level="WARNING") as logs:
            ld = cle.Loader(_unpaired_variant(), auto_load_libs=False, main_opts={"base_addr": BASE_ADDR})
        assert expected == binascii.hexlify(ld.memory.load(BASE_ADDR, 0x1C))
        assert len(logs.records) == 2


if __name__ == "__main__":
    unittest.main()
