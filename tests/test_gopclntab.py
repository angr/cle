from __future__ import annotations

import os
import struct
import unittest

import pytest
from elftools.elf.elffile import ELFFile

import cle
from cle.backends.gopclntab import GoPclntab

TEST_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)

# A stripped Go binary whose pclntab magic and textStart field have been clobbered.
DAMAGED_BINARY = "/workspace/swoop/binaries/original/starling"


def _symtab_functions(path):
    """
    STT_FUNC symbols of an ELF, as {address: {names}}.
    """
    with open(path, "rb") as fp:
        section = ELFFile(fp).get_section_by_name(".symtab")
        out = {}
        for sym in section.iter_symbols():
            if sym.entry.st_info.type == "STT_FUNC":
                out.setdefault(sym.entry.st_value, set()).add(sym.name)
        return out


class TestGoPclntab(unittest.TestCase):
    def test_clean_binary(self):
        path = os.path.join(TEST_LOCATION, "x86_64", "langdetect_go")
        ld = cle.Loader(path, auto_load_libs=False)
        tab = ld.main_object.gopclntab

        assert tab is not None
        assert tab.go_version == (1, 20)
        assert tab.ptr_size == 8
        assert tab.min_lc == 1
        assert tab.text_start == 0x401000  # valid in the header, no fallback needed
        assert len(tab.functions) == 1557
        assert all(f.size > 0 for f in tab.functions)
        assert [f.addr for f in tab.functions] == sorted(f.addr for f in tab.functions)

    def test_clean_binary_matches_symtab(self):
        # Every pclntab function must correspond to a symbol table entry. The Go linker records
        # assembly functions under an extra ".abi0" suffix in the symbol table only.
        path = os.path.join(TEST_LOCATION, "x86_64", "langdetect_go")
        tab = cle.Loader(path, auto_load_libs=False).main_object.gopclntab
        symtab = _symtab_functions(path)

        exact = abi0 = 0
        for func in tab.functions:
            names = symtab.get(func.addr, set())
            if func.name in names:
                exact += 1
            elif func.name + ".abi0" in names:
                abi0 += 1
        assert exact == 1442
        assert abi0 == 115
        assert exact + abi0 == len(tab.functions)

    def test_clean_binary_does_not_duplicate_symbols(self):
        # The symbol table already covers every Go function here, so nothing should be added.
        path = os.path.join(TEST_LOCATION, "x86_64", "langdetect_go")
        ld = cle.Loader(path, auto_load_libs=False)
        assert not [s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]

    def test_pie_binary(self):
        path = os.path.join(TEST_LOCATION, "x86_64", "langdetect_go_dyn")
        tab = cle.Loader(path, auto_load_libs=False).main_object.gopclntab
        assert tab is not None
        assert len(tab.functions) == 1574
        # textStart is runtime.text, which is past the start of .text
        assert tab.text_start == 0x4023E0

    @pytest.mark.skipif(not os.path.isfile(DAMAGED_BINARY), reason="binary is not available")
    def test_damaged_header(self):
        ld = cle.Loader(DAMAGED_BINARY, auto_load_libs=False)
        obj = ld.main_object
        tab = obj.gopclntab

        assert tab is not None
        assert tab.magic == 0xD7958606  # clobbered
        assert tab.go_version is None
        assert tab.text_start == 0x401000  # recovered from .text; the header field is zero
        assert len(tab.functions) == 6079

        symbols = [s for s in obj.symbols if isinstance(s, cle.GoSymbol)]
        assert len(symbols) == 6079
        assert all(s.type == cle.SymbolType.TYPE_FUNCTION for s in symbols)
        assert all(s.is_function for s in symbols)

        by_addr = {s.rebased_addr: s for s in symbols}
        for func in tab.functions:
            assert by_addr[func.addr].name == func.name
            assert by_addr[func.addr].size == func.size

        # this binary was obfuscated: the name offsets of most functions were zeroed out, so
        # only 863 of the 6079 entries still carry a name
        assert len({f.name for f in tab.functions}) == 864
        assert sum(1 for f in tab.functions if not f.name) == 5216

        assert ld.find_symbol("runtime.GOMAXPROCS") is not None
        assert obj.get_symbol("runtime.Caller").rebased_addr in by_addr

    def test_non_go_binary(self):
        path = os.path.join(TEST_LOCATION, "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)
        assert ld.main_object.gopclntab is None
        assert not [s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]

    def test_rejects_garbage(self):
        assert GoPclntab.parse(b"") is None
        assert GoPclntab.parse(b"\xff" * 4096) is None
        assert GoPclntab.parse(os.urandom(4096)) is None

    def test_rejects_bad_header_fields(self):
        path = os.path.join(TEST_LOCATION, "x86_64", "langdetect_go")
        with open(path, "rb") as fp:
            data = ELFFile(fp).get_section_by_name(".gopclntab").data()
        assert GoPclntab.parse(data) is not None

        def mutate(offset, value, fmt="<Q"):
            return data[:offset] + struct.pack(fmt, value) + data[offset + struct.calcsize(fmt) :]

        assert GoPclntab.parse(mutate(7, 3, "<B")) is None  # ptrSize
        assert GoPclntab.parse(mutate(6, 3, "<B")) is None  # minLC
        assert GoPclntab.parse(mutate(4, 1, "<H")) is None  # padding
        assert GoPclntab.parse(mutate(8, 1 << 40)) is None  # nfunc
        assert GoPclntab.parse(mutate(8, 0)) is None  # nfunc
        assert GoPclntab.parse(mutate(16, 1 << 40)) is None  # nfiles
        assert GoPclntab.parse(mutate(32, 0)) is None  # funcnameOffset before the header
        assert GoPclntab.parse(mutate(40, 0)) is None  # cuOffset out of order
        assert GoPclntab.parse(mutate(64, len(data))) is None  # pclnOffset past the end

        # a zeroed textStart is only usable together with a fallback
        zeroed = mutate(24, 0)
        assert GoPclntab.parse(zeroed) is None
        assert GoPclntab.parse(zeroed, text_start_fallback=0x401000).text_start == 0x401000

        # non-monotonic function entry offsets
        pcln_off = struct.unpack_from("<Q", data, 64)[0]
        assert GoPclntab.parse(mutate(pcln_off + 8, 0, "<I")) is None


if __name__ == "__main__":
    unittest.main()
