# pylint: disable=missing-class-docstring
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from typing import NamedTuple

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import cle
from cle.backends import Symbol
from cle.backends.elf.relocation.arm import R_ARM_THM_CALL

BINARIES = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

# The mbed GCC ARM build for the Nucleo L152RE, the same build that produced
# tests/armel/i2c_api.o, ships this 43-member static library. Every member is a Thumb ET_REL
# object whose calls into the mbed HAL are REL R_ARM_THM_CALL and R_ARM_THM_JUMP24 relocations, so
# the addends come out of the instructions themselves. CLE gives each member its own
# rebase_granularity boundary and maps the extern object after all of them, which leaves the calls
# to the extern stubs anywhere from a few hundred KiB to 42 MiB away -- both sides of a Thumb
# branch's reach in a single load.
ARCHIVE = os.path.join(
    BINARIES,
    os.path.join("tests_src", "i2c_master_read-nucleol152re", "mbed", "TARGET_NUCLEO_L152RE", "TOOLCHAIN_GCC_ARM"),
    "libmbed.a",
)

# One object out of that same build, holding 51 R_ARM_THM_CALL and 11 R_ARM_THM_JUMP24
# relocations, all REL.
OBJECT = os.path.join(BINARIES, os.path.join("tests", "armel"), "i2c_api.o")

THM_BRANCH_RELOC_TYPES = (
    ENUM_RELOC_TYPE_ARM["R_ARM_THM_CALL"],
    ENUM_RELOC_TYPE_ARM["R_ARM_THM_JUMP24"],
)

#: A 32-bit Thumb BL/B.W carries a signed 25-bit byte displacement from PC, so it reaches
#: [-16 MiB, 16 MiB).
THM_BRANCH_REACH = 1 << 24

#: The reach CLE used to permit, having sign extended the displacement from bit 23 rather than
#: bit 24.
NARROW_THM_BRANCH_REACH = 1 << 23


def decode_thm_branch(data: bytes, addr: int) -> int:
    """
    Decode the branch target of the 32-bit Thumb BL/B.W made of the four bytes ``data`` and
    placed at ``addr``.
    """
    hi = data[0] | (data[1] << 8)
    lo = data[2] | (data[3] << 8)
    sign = (hi >> 10) & 1
    i1 = 1 - (((lo >> 13) & 1) ^ sign)
    i2 = 1 - (((lo >> 11) & 1) ^ sign)
    imm = (sign << 24) | (i1 << 23) | (i2 << 22) | ((hi & 0x3FF) << 12) | ((lo & 0x7FF) << 1)
    if sign:
        imm -= 1 << 25
    return addr + 4 + imm


def encode_thm_branch(data: bytes, imm: int) -> bytes:
    """
    Rewrite the displacement of the 32-bit Thumb BL/B.W made of the four bytes ``data``, leaving
    the rest of the encoding alone.
    """
    hi = data[0] | (data[1] << 8)
    lo = data[2] | (data[3] << 8)
    sign = (imm >> 24) & 1
    j1 = 1 - (((imm >> 23) & 1) ^ sign)
    j2 = 1 - (((imm >> 22) & 1) ^ sign)
    hi = (hi & ~0x7FF) | (sign << 10) | ((imm >> 12) & 0x3FF)
    lo = (lo & ~0x2FFF) | (j1 << 13) | (j2 << 11) | ((imm >> 1) & 0x7FF)
    return bytes((hi & 0xFF, hi >> 8, lo & 0xFF, lo >> 8))


def rewrite_undefined_branch_addends(src: str, dst: str, addend: int) -> None:
    """
    Copy the object at ``src`` to ``dst``, giving every Thumb branch against an undefined symbol
    an implicit addend of ``addend``.

    Only the four instruction bytes at each relocation site change; the container, its sections,
    its symbols and its relocations are the ones the toolchain emitted.
    """
    shutil.copyfile(src, dst)

    offsets = []
    with open(dst, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            symtab = elf.get_section(section["sh_link"])
            assert isinstance(symtab, SymbolTableSection)
            target = elf.get_section(section["sh_info"])
            for reloc in section.iter_relocations():
                if reloc["r_info_type"] not in THM_BRANCH_RELOC_TYPES:
                    continue
                if symtab.get_symbol(reloc["r_info_sym"])["st_shndx"] != "SHN_UNDEF":
                    continue
                offsets.append(target["sh_offset"] + reloc["r_offset"])

    assert offsets
    with open(dst, "r+b") as f:
        for offset in offsets:
            f.seek(offset)
            data = f.read(4)
            f.seek(offset)
            f.write(encode_thm_branch(data, addend & 0x1FFFFFF))


class Branch(NamedTuple):
    symbol: Symbol
    #: The displacement from the branch's PC to the symbol, which is what has to be encoded.
    displacement: int
    #: The branch target CLE actually encoded.
    target: int

    @property
    def in_reach(self) -> bool:
        return -THM_BRANCH_REACH <= self.displacement < THM_BRANCH_REACH

    @property
    def lands_on_symbol(self) -> bool:
        return self.target == self.symbol.rebased_addr & ~1


def thm_branches(ld: cle.Loader) -> list[Branch]:
    """
    Every resolved Thumb branch relocation in the loader, with the displacement it had to encode
    and the target it ended up encoding.
    """
    branches = []
    for obj in ld.all_objects:
        for reloc in obj.relocs:
            resolved = reloc.resolvedby
            if not isinstance(reloc, R_ARM_THM_CALL) or resolved is None:
                continue
            place = reloc.rebased_addr
            branches.append(
                Branch(
                    resolved,
                    (resolved.rebased_addr & ~1) - (place + 4),
                    decode_thm_branch(ld.memory.load(place, 4), place),
                )
            )
    return branches


class TestArmRelocations(unittest.TestCase):
    @staticmethod
    def test_archive_calls_past_8mb():
        # Spread over 43 archive members, plenty of the calls to the extern stubs land past
        # 8 MiB. That is beyond a signed 24-bit displacement but well inside the signed 25-bit
        # field a Thumb BL actually carries, so they have to be encoded, not rejected.
        ld = cle.Loader(ARCHIVE, auto_load_libs=False)

        in_reach = [branch for branch in thm_branches(ld) if branch.in_reach]
        assert in_reach
        assert any(abs(branch.displacement) > NARROW_THM_BRANCH_REACH for branch in in_reach)
        for branch in in_reach:
            assert branch.lands_on_symbol

    def test_archive_calls_out_of_reach_are_not_fatal(self):
        # The far end of the same archive is past even a 25-bit displacement. Those calls cannot
        # be encoded, but that must not cost the caller the rest of the archive, and it must not
        # disturb the calls that are still in reach.
        with self.assertLogs("cle.backends.elf.relocation.arm", level="WARNING") as logs:
            ld = cle.Loader(ARCHIVE, auto_load_libs=False)

        branches = thm_branches(ld)
        assert any(not branch.in_reach for branch in branches)
        assert any("out of range" in record.getMessage() for record in logs.records)
        assert all(branch.lands_on_symbol for branch in branches if branch.in_reach)

    @staticmethod
    def test_wide_implicit_addend():
        # An implicit addend of at least 8 MiB only survives if the whole 25-bit displacement is
        # read back out of the instruction. No fixture carries one: a toolchain leaves a branch
        # that wide only when it relocates against a section symbol in a section that big. So the
        # case is made by rewriting the displacements of a real object's branches, which changes
        # four bytes per branch and leaves its sections, symbols and relocations alone.
        addend = -0x800004
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, os.path.basename(OBJECT))
            rewrite_undefined_branch_addends(OBJECT, path, addend)
            ld = cle.Loader(path, auto_load_libs=False, main_opts={"base_addr": 0x1000000})

            branches = [b for b in thm_branches(ld) if b.symbol.owner is ld.extern_object]
            assert branches
            for branch in branches:
                assert branch.target == (branch.symbol.rebased_addr + addend + 4) & ~1


if __name__ == "__main__":
    unittest.main()
