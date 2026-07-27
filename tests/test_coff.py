# pylint:disable=no-self-use
from __future__ import annotations

import os
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

import archinfo
import pytest

import cle
from cle.backends.coff import CoffRelocation, CoffRelocationDIR32, CoffRelocationREL32

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def _coff_with_long_section_names(section_names: list[str]) -> bytes:
    string_offsets = []
    string_payload = bytearray()
    for name in section_names:
        string_offsets.append(4 + len(string_payload))
        string_payload.extend(name.encode("ascii") + b"\0")

    raw_data_offset = 20 + 40 * len(section_names)
    section_table = b"".join(
        struct.pack(
            "<8sLLLLLLHHL",
            f"/{offset}".encode().ljust(8, b"\0"),
            0,
            0,
            1,
            raw_data_offset + index,
            0,
            0,
            0,
            0,
            0x40300040,
        )
        for index, offset in enumerate(string_offsets)
    )
    raw_data = bytes(len(section_names))
    symbol_table_offset = raw_data_offset + len(raw_data)
    header = struct.pack(
        "<HHLLLHH",
        0x14C,
        len(section_names),
        0,
        symbol_table_offset,
        0,
        0,
        0,
    )
    string_table = struct.pack("<L", 4 + len(string_payload)) + string_payload
    return header + section_table + raw_data + string_table


class TestCoff(unittest.TestCase):
    """
    Test COFF loader.
    """

    def test_x86(self):
        exe = os.path.join(TEST_BASE, "tests", "x86", "fauxware.obj")
        ld = cle.Loader(exe, auto_load_libs=True)
        symbol_names = {sym.name for sym in ld.main_object.symbols}
        assert "_main" in symbol_names
        assert "_accepted" in symbol_names
        assert "_rejected" in symbol_names
        assert "_authenticate" in symbol_names

    def test_x86_64(self):
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.obj")
        ld = cle.Loader(exe, auto_load_libs=True)
        symbol_names = {sym.name for sym in ld.main_object.symbols}
        assert "main" in symbol_names
        assert "accepted" in symbol_names
        assert "rejected" in symbol_names
        assert "authenticate" in symbol_names


def test_long_section_names_use_string_table_offsets(tmp_path: Path):
    obj = tmp_path / "long-section-names.obj"
    obj.write_bytes(_coff_with_long_section_names([".rdata$zzz", ".eh_frame"]))

    loaded = cle.Loader(obj, auto_load_libs=False)

    assert [section.name for section in loaded.main_object.sections] == [".rdata$zzz", ".eh_frame"]


def _coff_owner(initial_data: bytes = b"\0" * 8):
    arch = archinfo.ArchX86()
    memory = cle.Clemory(arch, root=True)
    memory.add_backer(0, initial_data)
    return SimpleNamespace(
        arch=arch,
        imports={},
        linked_base=0,
        mapped_base=0,
        memory=memory,
    )


class _ConstantCoffRelocation(CoffRelocation):
    def __init__(self, owner, value: int, pack_format: str):
        super().__init__(owner, None, 0)
        self._value = value
        self.PACK_FORMAT = pack_format

    @property
    def value(self):
        return self._value


@pytest.mark.parametrize(("pack_format", "bits"), [("<H", 16), ("<I", 32), ("<Q", 64)])
def test_coff_relocation_wraps_at_field_width(pack_format: str, bits: int):
    modulus = 1 << bits
    for value in (-1, modulus - 1, modulus, modulus + 1):
        owner = _coff_owner()
        relocation = _ConstantCoffRelocation(owner, value, pack_format)

        assert relocation.relocate()
        assert owner.memory.load(0, bits // 8) == (value % modulus).to_bytes(bits // 8, "little")


def test_coff_dir32_wraps_real_boost_addend():
    # Exact relocation arithmetic from Boost object
    # 89bdc1f3ef8414040410e75304d413cd027191f56bfd577639f3cb0193fd0fa1.
    owner = _coff_owner(b"\xfa\xff\xff\xff")
    relocation = CoffRelocationDIR32(owner, None, 0)
    relocation.resolvedby = SimpleNamespace(rebased_addr=0x432388)

    assert relocation.relocate()
    assert owner.memory.load(0, 4) == struct.pack("<I", 0x432382)


def test_coff_rel32_retains_signed_pc_relative_semantics():
    owner = _coff_owner(b"\xfa\xff\xff\xff")
    owner.linked_base = owner.mapped_base = 0x400000
    relocation = CoffRelocationREL32(owner, None, 0x100)
    owner.memory.add_backer(0x100, b"\xfa\xff\xff\xff")
    relocation.resolvedby = SimpleNamespace(rebased_addr=0x400080)

    assert relocation.value == -0x8A
    assert relocation.relocate()
    assert owner.memory.load(0x100, 4) == struct.pack("<i", -0x8A)


if __name__ == "__main__":
    unittest.main()
