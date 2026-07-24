from __future__ import annotations

import struct
from types import SimpleNamespace
from typing import Any

import archinfo

from cle.backends.coff import IMAGE_SYM_CLASS
from cle.backends.pe.pe import PE
from cle.backends.symbol import SymbolType


class _SymbolList(list):
    """Minimal symbol container used by the fixture-free PE tests."""

    def add(self, symbol) -> None:
        self.append(symbol)


def _make_pe(raw_data: bytes = b"", exports=()) -> Any:
    pe: Any = object.__new__(PE)
    pe._arch = archinfo.ArchAMD64()
    pe._raw_data = raw_data
    pe._pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(PointerToSymbolTable=0, NumberOfSymbols=len(raw_data) // 18),
        sections=[SimpleNamespace(VirtualAddress=0x1000)],
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=exports),
    )
    pe.symbols = _SymbolList()
    pe._exports = {}
    pe._ordinal_exports = {}
    pe.deps = []
    return pe


def _coff_symbol(name: bytes, value: int, section: int, type_: int, storage_class: int) -> bytes:
    return struct.pack("<8sIhHBB", name, value, section, type_, storage_class, 0)


def test_coff_symbol_type_hints_only_include_external_definitions():
    raw_data = b"".join(
        [
            _coff_symbol(b"function", 0x10, 1, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"object", 0x20, 1, 0, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"static", 0x30, 1, 0, IMAGE_SYM_CLASS.STATIC),
            _coff_symbol(b"undefined", 0, 0, 0x20, IMAGE_SYM_CLASS.EXTERNAL),
            _coff_symbol(b"other", 0x40, 1, 0x10, IMAGE_SYM_CLASS.EXTERNAL),
        ]
    )
    pe = _make_pe(raw_data + b"\0\0\0\0")

    symbol_types = pe._load_symbols_from_coff_header()

    assert symbol_types == {
        0x1010: {SymbolType.TYPE_FUNCTION},
        0x1020: {SymbolType.TYPE_OBJECT},
    }
    assert {symbol.name for symbol in pe.symbols} == {"function", "object", "static"}


def test_exports_inherit_only_unambiguous_coff_symbol_types():
    exports = [
        SimpleNamespace(name=b"data", address=0x1010, forwarder=None, ordinal=1),
        SimpleNamespace(name=b"ambiguous", address=0x1020, forwarder=None, ordinal=2),
        SimpleNamespace(name=b"missing", address=0x1030, forwarder=None, ordinal=3),
        SimpleNamespace(name=b"forwarded", address=0x1040, forwarder=b"other.target", ordinal=4),
    ]
    pe = _make_pe(exports=exports)

    pe._handle_exports(
        {
            0x1010: {SymbolType.TYPE_OBJECT},
            0x1020: {SymbolType.TYPE_FUNCTION, SymbolType.TYPE_OBJECT},
            0x1040: {SymbolType.TYPE_OBJECT},
        }
    )

    assert pe._exports["data"].type is SymbolType.TYPE_OBJECT
    assert pe._exports["ambiguous"].type is SymbolType.TYPE_FUNCTION
    assert pe._exports["missing"].type is SymbolType.TYPE_FUNCTION
    assert pe._exports["forwarded"].type is SymbolType.TYPE_FUNCTION
    assert pe.deps == ["other.dll"]
