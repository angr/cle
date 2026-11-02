from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

from cle.backends.elf import elf as elf_module
from cle.backends.elf.elf import ELF


class _SymbolTable:
    """Minimal pyelftools symbol table used to isolate ``ELF.get_symbol``."""

    def __init__(self, count: int, symbol: Any = None, sh_type: str | None = "SHT_SYMTAB"):
        self.count = count
        self.symbol = symbol
        self.lookups = []
        self.header = {} if sh_type is None else {"sh_type": sh_type}

    def num_symbols(self):
        return self.count

    def get_symbol(self, index):
        self.lookups.append(index)
        return self.symbol


@pytest.mark.parametrize("index", (-1, 3))
def test_out_of_range_symbol_index(index):
    elf = cast(Any, ELF.__new__(ELF))
    symbol_table = _SymbolTable(3)

    assert elf.get_symbol(index, symbol_table) is None
    assert not symbol_table.lookups


def test_unknown_symbol_version(monkeypatch):
    elf = cast(Any, ELF.__new__(ELF))
    symbol_table = _SymbolTable(3, object())
    elf.hashtable = SimpleNamespace(symtab=symbol_table)
    elf._vertable = SimpleNamespace(get_symbol=lambda _: SimpleNamespace(entry=SimpleNamespace(ndx=120)))
    elf._versions = {0: "*local*", 1: "*global*"}
    elf._symbol_cache = {}
    elf._symbols_by_name = {}
    elf._desperate_for_symbols = False
    monkeypatch.setattr(ELF, "_symbol_to_tuple", staticmethod(lambda _: ("symbol",)))
    monkeypatch.setattr(
        elf_module,
        "ELFSymbol",
        lambda *_: SimpleNamespace(name="", version=None),
    )

    symbol = elf.get_symbol(2, symbol_table)

    assert symbol.version is None
    assert symbol_table.lookups == [2]


def test_synthetic_symbol_table_does_not_use_unreliable_count(monkeypatch):
    elf = cast(Any, ELF.__new__(ELF))
    symbol_table = _SymbolTable(1, object(), sh_type=None)
    elf.hashtable = SimpleNamespace(symtab=symbol_table)
    elf._vertable = None
    elf._versions = None
    elf._symbol_cache = {}
    elf._symbols_by_name = {}
    elf._desperate_for_symbols = False
    monkeypatch.setattr(ELF, "_symbol_to_tuple", staticmethod(lambda _: ("symbol",)))
    monkeypatch.setattr(
        elf_module,
        "ELFSymbol",
        lambda *_: SimpleNamespace(name="", version=None),
    )

    assert elf.get_symbol(2, symbol_table) is not None
    assert symbol_table.lookups == [2]
