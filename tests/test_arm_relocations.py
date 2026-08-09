# pylint: disable=missing-class-docstring
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_ARM
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

import cle
from cle.backends import Symbol
from cle.backends.elf.relocation.arm import R_ARM_THM_CALL

# An ET_REL ARM object holding 51 R_ARM_THM_CALL and 11 R_ARM_THM_JUMP24 relocations, all REL,
# so the addends come out of the instructions themselves.
TEST_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
    os.path.join("armel", "i2c_api.o"),
)

THM_BRANCH_RELOC_TYPES = (
    ENUM_RELOC_TYPE_ARM["R_ARM_THM_CALL"],
    ENUM_RELOC_TYPE_ARM["R_ARM_THM_JUMP24"],
)

MIB = 1024 * 1024


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


def write_static_archive(path: str, member: str, count: int) -> None:
    """
    Write an ``ar`` archive holding ``count`` copies of the object file ``member``.
    """
    with open(member, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:
        f.write(b"!<arch>\n")
        for i in range(count):
            name = f"m{i:02d}.o/".encode().ljust(16)
            f.write(name + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6))
            f.write(b"100644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n")
            f.write(data)
            if len(data) % 2:
                f.write(b"\n")


def rewrite_undefined_branch_addends(src: str, dst: str, addend: int) -> None:
    """
    Copy the object at ``src`` to ``dst``, giving every Thumb branch against an undefined symbol
    an implicit addend of ``addend``.
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


def thm_branches(ld: cle.Loader) -> list[tuple[Symbol, int, int]]:
    """
    For every resolved Thumb branch relocation in the loader: the symbol it resolved to, the
    distance CLE had to encode, and the branch target it actually encoded.
    """
    branches = []
    for obj in ld.all_objects:
        for reloc in obj.relocs:
            resolved = reloc.resolvedby
            if not isinstance(reloc, R_ARM_THM_CALL) or resolved is None:
                continue
            reach = abs(resolved.rebased_addr - reloc.rebased_addr)
            target = decode_thm_branch(ld.memory.load(reloc.rebased_addr, 4), reloc.rebased_addr)
            branches.append((resolved, reach, target))
    return branches


class TestArmRelocations(unittest.TestCase):
    @staticmethod
    def test_archive_calls_past_8mb():
        # CLE gives every archive member its own rebase_granularity boundary and maps the extern
        # object after all of them, so a dozen members put the calls to the extern stubs more than
        # 8 MiB away. That is past a signed 24-bit displacement but well inside the signed 25-bit
        # field a Thumb BL actually carries.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "libthm.a")
            write_static_archive(path, TEST_FILE, 14)
            ld = cle.Loader(path, auto_load_libs=False)

            branches = thm_branches(ld)
            assert branches
            assert max(reach for _, reach, _ in branches) > 8 * MIB
            for symbol, _, target in branches:
                assert target == symbol.rebased_addr & ~1

    def test_archive_calls_out_of_reach_are_not_fatal(self):
        # Enough members and the extern object lands past even a 25-bit displacement. Those calls
        # cannot be encoded, but that must not cost the caller the rest of the archive, and it must
        # not disturb the calls that are still in reach.
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "libthm.a")
            write_static_archive(path, TEST_FILE, 24)
            with self.assertLogs("cle.backends.elf.relocation.arm", level="WARNING") as logs:
                ld = cle.Loader(path, auto_load_libs=False)

            branches = thm_branches(ld)
            assert branches
            assert max(reach for _, reach, _ in branches) > 16 * MIB
            assert any("out of range" in record.getMessage() for record in logs.records)
            for symbol, reach, target in branches:
                if reach <= 8 * MIB:
                    assert target == symbol.rebased_addr & ~1

    @staticmethod
    def test_wide_implicit_addend():
        # An implicit addend of at least 8 MiB only survives if the whole 25-bit displacement is
        # read back out of the instruction.
        addend = -0x800004
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "i2c_api.o")
            rewrite_undefined_branch_addends(TEST_FILE, path, addend)
            ld = cle.Loader(path, auto_load_libs=False, main_opts={"base_addr": 0x1000000})

            branches = [b for b in thm_branches(ld) if b[0].owner is ld.extern_object]
            assert branches
            for symbol, _, target in branches:
                assert target == (symbol.rebased_addr + addend + 4) & ~1


if __name__ == "__main__":
    unittest.main()
