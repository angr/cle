# pylint:disable=no-self-use
from __future__ import annotations

import os
import struct
import unittest
from pathlib import Path

import cle

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


if __name__ == "__main__":
    unittest.main()
