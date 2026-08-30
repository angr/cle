# pylint:disable=no-self-use
from __future__ import annotations

import os
import unittest

import archinfo

import cle
from cle.backends.elf.relocation.generic import MipsGlobalReloc, MipsLocalReloc

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))


class TestMipsN32(unittest.TestCase):
    """
    The n32 and O64 ABIs put a 64-bit MIPS instruction stream in an ELFCLASS32 container. Taking
    the instruction set from the container gives 32-bit MIPS and nothing decodes; taking the word
    size from the instruction set instead gives 8-byte reads and writes into the file's 4-byte
    relocation slots and GOT entries.
    """

    def _load(self, name):
        return cle.Loader(os.path.join(test_location, "mipsn32", name), auto_load_libs=False)

    def test_n32_big_endian(self):
        arch = self._load("n32_be_static").main_object.arch
        assert isinstance(arch, archinfo.ArchMIPSN32)
        assert arch.memory_endness == archinfo.Endness.BE
        assert arch.bits == 32
        assert arch.vex_arch == "VexArchMIPS64"

    def test_n32_little_endian(self):
        arch = self._load("n32_el_dynamic").main_object.arch
        assert isinstance(arch, archinfo.ArchMIPSN32)
        assert arch.memory_endness == archinfo.Endness.LE

    def test_n32_relocatable_object(self):
        arch = self._load("n32_el.o").main_object.arch
        assert isinstance(arch, archinfo.ArchMIPSN32)

    def test_o64(self):
        for name in ("o64_el_static", "o64_el.o"):
            arch = self._load(name).main_object.arch
            assert isinstance(arch, archinfo.ArchMIPSN32), name

    def test_o32_is_still_mips32(self):
        # The detection keys on the ABI bits, so a plain o32 object must be unaffected even when
        # it was built for a 64-bit MIPS processor.
        for name in ("mips/fauxware", "mipsel/fauxware"):
            ld = cle.Loader(os.path.join(test_location, name), auto_load_libs=False)
            assert type(ld.main_object.arch) is archinfo.ArchMIPS32, name

    def test_n64_is_still_mips64(self):
        ld = cle.Loader(os.path.join(test_location, "mips64/test_arrays"), auto_load_libs=False)
        assert type(ld.main_object.arch) is archinfo.ArchMIPS64

    def test_got_and_relocation_slots_stay_four_bytes(self):
        obj = self._load("n32_el_dynamic").main_object
        assert obj.arch.bytes == 4

        # Every relocation must apply without raising. Resolving n32 to a 64-bit architecture
        # reads an 8-byte implicit addend out of a 4-byte REL slot and writes 8 bytes back over
        # the neighbouring word, which shows up here as a KeyError off the end of the GOT.
        for reloc in obj.relocs:
            reloc.relocate()

        # The MIPS GOT is strided by the word size. At 8 bytes the entries would land on every
        # other slot and run off the end of the section.
        got = sorted(r.dest_addr for r in obj.relocs if isinstance(r, MipsGlobalReloc | MipsLocalReloc))
        assert got, "expected a classic MIPS GOT"
        assert min(b - a for a, b in zip(got, got[1:])) == 4
        got_section = obj.sections_map[".got"]
        assert got[-1] + 4 <= got_section.vaddr + got_section.memsize


if __name__ == "__main__":
    unittest.main()
