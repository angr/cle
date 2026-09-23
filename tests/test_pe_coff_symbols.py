from __future__ import annotations

import os

import cle
from cle.backends.symbol import SymbolType

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def load(*parts):
    return cle.Loader(os.path.join(TEST_BASE, "tests", *parts), auto_load_libs=False).main_object


def symbol(obj, name):
    found = obj.get_symbol(name)
    assert found is not None, f"{name} is not among the symbols cle loaded"
    return found


def exports(obj):
    return {each.name: each for each in obj.symbols if each.is_export}


def test_coff_symbols_carry_the_type_the_table_declares():
    # A MinGW image: 1341 symbol records, the names too long for the eight-byte field in a
    # string table behind them, and auxiliary records in between.
    obj = load("x86_64", "cfg_0_pe")

    assert symbol(obj, "main").type is SymbolType.TYPE_FUNCTION
    assert symbol(obj, "func").type is SymbolType.TYPE_FUNCTION
    assert symbol(obj, "startinfo").type is SymbolType.TYPE_OBJECT
    # A local definition: loaded like the rest, but it cannot describe an export.
    assert symbol(obj, "managedapp").type is SymbolType.TYPE_OBJECT
    # Only the string table can produce this one.
    assert symbol(obj, "__fu0__set_invalid_parameter_handler").type is SymbolType.TYPE_OBJECT


def test_a_symbol_table_outside_the_file_loads_no_symbols():
    # The packed copy keeps the unpacked one's symbol-table pointer and count -- 0x12e00 and
    # 1292 records, as tests/x86/windows/not_packed_pe32.exe has -- in a file 0xbe00 bytes
    # shorter, so the table it describes ends past the end of the file.
    obj = load("x86", "windows", "packed_pe32.exe")

    assert obj.symbols
    assert all(symbol.is_import for symbol in obj.symbols)


def test_exports_take_the_type_of_their_coff_definition():
    obj = load("x86_64", "windows", "coff_export_types.dll")

    assert exports(obj)["exported_counter"].type is SymbolType.TYPE_OBJECT
    assert exports(obj)["exported_function"].type is SymbolType.TYPE_FUNCTION


def test_a_forwarded_export_is_a_function_and_names_its_library():
    obj = load("x86_64", "windows", "coff_export_types.dll")

    forwarded = exports(obj)["forwarded_function"]
    assert forwarded.forwarder == "user32.MessageBoxA"
    assert forwarded.type is SymbolType.TYPE_FUNCTION
    # The import directory names only kernel32 and msvcrt, so the forwarder is the only
    # thing that puts user32 among the dependencies.
    assert "user32.dll" in obj.deps


def test_exports_are_functions_when_no_symbol_table_types_them():
    obj = load("x86_64", "windows", "msvcr120.dll")

    assert {symbol.type for symbol in exports(obj).values()} == {SymbolType.TYPE_FUNCTION}
