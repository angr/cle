# pylint:disable=no-self-use
from __future__ import annotations

import os
import struct
import unittest
from io import BytesIO

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_REL_I386_DIR32 = 0x0006
IMAGE_REL_I386_REL32 = 0x0014
IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SCN_TEXT = 0x60000020  # CNT_CODE | MEM_EXECUTE | MEM_READ

COFF_HEADER = struct.Struct("<HHLLLHH")
COFF_SECTION_HEADER = struct.Struct("<8sLLLLLLHHL")
COFF_SYMBOL = struct.Struct("<8sLhHBB")
COFF_RELOCATION = struct.Struct("<LLH")


class CoffObjectWriter:
    """
    Assembles a minimal i386 COFF object in memory.

    No object in the ``binaries`` repository has a long section name or a relocation field that
    wraps, so the tests below write their own input rather than checking in another compiled
    object.
    """

    def __init__(self):
        self._sections: list[dict] = []
        self._symbols: list[tuple[str, int, int]] = []
        self._string_table = bytearray()

    def add_section(self, name: str, data: bytes) -> int:
        """
        Append a section and return its one-based section number.
        """
        self._sections.append({"name": name, "data": data, "relocations": []})
        return len(self._sections)

    def add_symbol(self, name: str, value: int, section_number: int) -> int:
        """
        Append an external symbol defined at `value` bytes into `section_number`, and return its
        symbol table index.
        """
        self._symbols.append((name, value, section_number))
        return len(self._symbols) - 1

    def add_relocation(self, section_number: int, offset: int, symbol_index: int, reloc_type: int) -> None:
        self._sections[section_number - 1]["relocations"].append((offset, symbol_index, reloc_type))

    def section_offset(self, section_number: int) -> int:
        """
        File offset of a section's raw data. The COFF backend maps the whole file at
        `mapped_base` and uses PointerToRawData as each section's address, so this is also the
        section's offset within the loaded image.
        """
        offset = COFF_HEADER.size + COFF_SECTION_HEADER.size * len(self._sections)
        for section in self._sections[: section_number - 1]:
            offset += len(section["data"])
        return offset

    def build(self) -> bytes:
        raw_data_end = self.section_offset(len(self._sections) + 1)

        section_headers = bytearray()
        raw_data = bytearray()
        relocation_tables = bytearray()
        for section_number, section in enumerate(self._sections, start=1):
            relocations = section["relocations"]
            section_headers += COFF_SECTION_HEADER.pack(
                self._section_name(section["name"]),
                0,  # VirtualSize
                0,  # VirtualAddress
                len(section["data"]),  # SizeOfRawData
                self.section_offset(section_number),  # PointerToRawData
                raw_data_end + len(relocation_tables) if relocations else 0,  # PointerToRelocations
                0,  # PointerToLinenumbers
                len(relocations),  # NumberOfRelocations
                0,  # NumberOfLinenumbers
                IMAGE_SCN_TEXT,  # Characteristics
            )
            raw_data += section["data"]
            for offset, symbol_index, reloc_type in relocations:
                relocation_tables += COFF_RELOCATION.pack(offset, symbol_index, reloc_type)

        symbol_table = bytearray()
        for name, value, section_number in self._symbols:
            symbol_table += COFF_SYMBOL.pack(
                self._symbol_name(name),
                value,
                section_number,
                0,  # Type
                IMAGE_SYM_CLASS_EXTERNAL,
                0,  # NumberOfAuxSymbols
            )

        header = COFF_HEADER.pack(
            IMAGE_FILE_MACHINE_I386,
            len(self._sections),
            0,  # TimeDateStamp
            raw_data_end + len(relocation_tables),  # PointerToSymbolTable
            len(self._symbols),
            0,  # SizeOfOptionalHeader
            0,  # Characteristics
        )
        # The string table declares its own size in its first four bytes, and offsets into it
        # count from the start of that size field.
        string_table = struct.pack("<I", 4 + len(self._string_table)) + bytes(self._string_table)
        return bytes(header + section_headers + raw_data + relocation_tables + symbol_table) + string_table

    def _intern(self, name: str) -> int:
        offset = 4 + len(self._string_table)
        self._string_table += name.encode() + b"\0"
        return offset

    def _section_name(self, name: str) -> bytes:
        if len(name) <= 8:
            return name.encode().ljust(8, b"\0")
        # A long section name is a slash followed by a decimal string table offset.
        return f"/{self._intern(name)}".encode().ljust(8, b"\0")

    def _symbol_name(self, name: str) -> bytes:
        if len(name) <= 8:
            return name.encode().ljust(8, b"\0")
        # A long symbol name is a zero dword followed by a string table offset.
        return struct.pack("<II", 0, self._intern(name))


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

    def test_long_section_names_come_from_the_string_table(self):
        # `.rdata$zzz` and `.gcc_except_table` are what a stock mingw-w64 GCC emits; `.debug$S`
        # fits in the eight-byte field and so stays out of the string table.
        writer = CoffObjectWriter()
        writer.add_section(".rdata$zzz", b"\0" * 4)
        writer.add_section(".debug$S", b"\0" * 4)
        writer.add_section(".gcc_except_table", b"\0" * 4)
        # Both string table offsets used above are also valid symbol table indices here, so
        # reading them as indices loads the object with quietly wrong section names instead of
        # running off the end of the symbol table.
        for i in range(16):
            writer.add_symbol(f"_sym{i}", 0, 1)

        ld = cle.Loader(BytesIO(writer.build()), auto_load_libs=False)

        assert [section.name for section in ld.main_object.sections] == [
            ".rdata$zzz",
            ".debug$S",
            ".gcc_except_table",
        ]

    def test_dir32_relocation_wraps_at_the_field_width(self):
        addend = -6

        writer = CoffObjectWriter()
        text = writer.add_section(".text", struct.pack("<i", addend) + b"\0" * 12)
        target = writer.add_symbol("_target", 8, text)
        writer.add_relocation(text, 0, target, IMAGE_REL_I386_DIR32)

        ld = cle.Loader(BytesIO(writer.build()), auto_load_libs=False)
        target_symbol = ld.main_object.get_symbol("_target")
        assert target_symbol is not None

        # The addend is stored as its 32-bit pattern, 0xfffffffa, so adding the symbol's address
        # to it carries past the top of the field.
        field_addr = ld.main_object.mapped_base + writer.section_offset(text)
        assert ld.memory.load(field_addr, 4) == struct.pack("<I", (target_symbol.rebased_addr + addend) % 2**32)

    def test_rel32_relocation_encodes_a_negative_displacement(self):
        callee_offset = 0
        field_offset = 5
        addend = -4

        writer = CoffObjectWriter()
        text = writer.add_section(
            ".text",
            b"\xc3" * 4  # the callee body, at offset 0
            + b"\xe8"  # call rel32, whose displacement field starts at offset 5
            + struct.pack("<i", addend)
            + b"\x90" * 3,
        )
        callee = writer.add_symbol("_callee", callee_offset, text)
        writer.add_relocation(text, field_offset, callee, IMAGE_REL_I386_REL32)
        data = writer.build()

        # A backwards call has a negative displacement, which the field carries as a 32-bit
        # two's complement pattern. Both operands live in .text, so the result does not depend
        # on where the loader maps the object.
        expected = addend + callee_offset - (field_offset + 4)
        assert expected < 0

        unrelocated = cle.Loader(BytesIO(data), auto_load_libs=False, perform_relocations=False)
        assert unrelocated.main_object.relocs[0].value == expected

        ld = cle.Loader(BytesIO(data), auto_load_libs=False)
        field_addr = ld.main_object.mapped_base + writer.section_offset(text) + field_offset
        assert ld.memory.load(field_addr, 4) == struct.pack("<i", expected)


if __name__ == "__main__":
    unittest.main()
