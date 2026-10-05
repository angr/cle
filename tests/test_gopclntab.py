from __future__ import annotations

import os
import struct
import unittest

from elftools.elf.elffile import ELFFile

import cle
from cle.backends.gopclntab import (
    _LAYOUT_GO110,
    _LAYOUT_GO112,
    GO_FUNC_FLAG_ASM,
    GO_FUNC_FLAG_SP_WRITE,
    GO_FUNC_FLAG_TOP_FRAME,
    GoPclntab,
    _infer_packing,
)

TEST_LOCATION = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)

# A stripped Go binary whose pclntab magic and textStart field have been clobbered.
DAMAGED_BINARY = os.path.join(TEST_LOCATION, "x86_64", "starling")

# Cross-compiled from tests_src/language_detector/langdetect_go.go. A PE has no section for the
# pclntab: it is embedded in .rdata and has to be found by its magic. A Mach-O does have one,
# __gopclntab, which PCLNTAB_SECTION_NAMES already knows.
GO_PE_BINARY = os.path.join(TEST_LOCATION, "x86_64", "windows", "langdetect_go.exe")
GO_MACHO_BINARY = os.path.join(TEST_LOCATION, "aarch64", "langdetect_go.macho")

# A Go PE from the wild, stripped: its COFF symbol table names not one Go function.
STRIPPED_GO_PE_BINARY = os.path.join(
    TEST_LOCATION, "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
)

# binaries/tests_src/go/basics.go built by two toolchains
GO_TESTS = os.path.join(TEST_LOCATION, "x86_64", "go")
BASICS_1225 = os.path.join(GO_TESTS, "go1.22.5", "basics")
BASICS_1225_STRIPPED = os.path.join(GO_TESTS, "go1.22.5", "basics_stripped")
BASICS_1271 = os.path.join(GO_TESTS, "go1.27.1", "basics")
LANGDETECT = os.path.join(TEST_LOCATION, "x86_64", "langdetect_go")

# the same two programs built by the toolchains with the older table layouts (tests_src/go/build.sh
# LEGACY_VERSIONS and tests_src/language_detector/build_go_cross.sh)


def _basics(version, stripped=False):
    return os.path.join(GO_TESTS, version, "basics_stripped" if stripped else "basics")


def _langdetect(arch, version, fmt="elf"):
    name = f"langdetect_go_{version}"
    if fmt == "pe":
        return os.path.join(TEST_LOCATION, arch, "windows", name + ".exe")
    if fmt == "macho":
        return os.path.join(TEST_LOCATION, arch, name + ".macho")
    return os.path.join(TEST_LOCATION, arch, name)


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

    def test_pe_binary(self):
        obj = cle.Loader(GO_PE_BINARY, auto_load_libs=False).main_object
        tab = obj.gopclntab

        assert tab is not None
        assert ".gopclntab" not in obj.sections_map
        assert tab.go_version == (1, 20)
        assert tab.ptr_size == 8
        assert tab.min_lc == 1
        assert tab.text_start == 0x140001000
        assert len(tab.functions) == 1898
        assert all(f.size > 0 for f in tab.functions)
        assert [f.addr for f in tab.functions] == sorted(f.addr for f in tab.functions)

    def test_pe_binary_supplies_the_function_symbols(self):
        obj = cle.Loader(GO_PE_BINARY, auto_load_libs=False).main_object
        tab = obj.gopclntab
        assert tab is not None
        go_symbols = [s for s in obj.symbols if isinstance(s, cle.GoSymbol)]

        # 23 of the pclntab's entries are assembly routines the COFF symbol table already covers
        assert len(go_symbols) == 1875
        assert all(s.type == cle.SymbolType.TYPE_FUNCTION for s in go_symbols)
        assert sum(1 for s in obj.symbols if s.is_function) == 1945

        by_addr = {}
        for symbol in obj.symbols:
            by_addr.setdefault(symbol.rebased_addr, set()).add(symbol.name)
        assert all(func.name in by_addr[func.addr] for func in tab.functions)

        assert (sym := obj.get_symbol("runtime.main")) is not None and sym.rebased_addr == 0x140047E20
        assert (sym := obj.get_symbol("main.main")) is not None and sym.rebased_addr == 0x1400A73C0

    def test_stripped_pe_binary(self):
        obj = cle.Loader(STRIPPED_GO_PE_BINARY, auto_load_libs=False).main_object
        tab = obj.gopclntab

        assert tab is not None
        assert tab.text_start == 0x401000
        assert len(tab.functions) == 1821
        # nothing in this object's symbol table lands on a Go function, so every entry is added
        assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == 1821
        assert sum(1 for s in obj.symbols if s.is_function) == 1861
        assert (sym := obj.get_symbol("main.main")) is not None and sym.rebased_addr == 0x4B75C0

    def test_macho_binary(self):
        obj = cle.Loader(GO_MACHO_BINARY, auto_load_libs=False).main_object
        tab = obj.gopclntab

        assert tab is not None
        assert "__TEXT,__gopclntab" in obj.sections_map
        assert tab.go_version == (1, 20)
        assert tab.ptr_size == 8
        assert tab.min_lc == 4
        assert tab.text_start == 0x100001000
        assert len(tab.functions) == 1888
        assert [f.addr for f in tab.functions] == sorted(f.addr for f in tab.functions)

    def test_macho_binary_supplies_the_function_symbols(self):
        obj = cle.Loader(GO_MACHO_BINARY, auto_load_libs=False).main_object
        assert isinstance(obj, cle.MachO)
        tab = obj.gopclntab
        assert tab is not None
        go_symbols = [s for s in obj.symbols if isinstance(s, cle.GoSymbol)]

        # cle reports no Mach-O symbol as a function, so nothing here covers a pclntab address and
        # every entry is added, next to the underscore-prefixed name the symbol table already has
        assert len(go_symbols) == 1888
        assert all(s.type == cle.SymbolType.TYPE_FUNCTION for s in go_symbols)

        by_addr = {}
        for symbol in obj.symbols:
            by_addr.setdefault(symbol.rebased_addr, set()).add(symbol.name)
        assert all(func.name in by_addr[func.addr] for func in tab.functions)

        assert obj.get_symbol("runtime.main")[0].rebased_addr == 0x10003FF30
        assert obj.get_symbol("main.main")[0].rebased_addr == 0x10009D340

    def test_non_go_binaries(self):
        # One per format, each with a read-only section the magic scan now reaches, so that a
        # miss here means the scan ran and found nothing rather than that it never ran.
        for path, section in (
            (os.path.join(TEST_LOCATION, "x86_64", "fauxware"), ".rodata"),
            (os.path.join(TEST_LOCATION, "x86_64", "windows", "fauxware.exe"), ".rdata"),
            (os.path.join(TEST_LOCATION, "aarch64", "dyld_ios15.macho"), "__DATA_CONST,__const"),
        ):
            obj = cle.Loader(path, auto_load_libs=False).main_object
            assert section in obj.sections_map
            assert obj.gopclntab is None
            assert not [s for s in obj.symbols if isinstance(s, cle.GoSymbol)]

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


def _load(path):
    return cle.Loader(path, auto_load_libs=False).main_object.gopclntab


def _by_name(tab):
    return {f.name: f for f in tab.functions}


class TestGoPclntabFuncInfo(unittest.TestCase):
    """
    The per-function ``_func`` fields and the pc-value tables.

    Every expected number was produced by Go's own debug/gosym (its ``_func`` field accessors and
    ``step`` decoder, exported from a vendored copy and run with go1.22.5 over the same binaries).
    ``go build -gcflags=-S`` agrees on the sizes: ``main.parse args=0x10``, ``main.fib args=0x8
    locals=0x18``, ``main.main args=0``.
    """

    # per binary: entries of main.parse/fib/main, (funcID, deferreturn) of runtime.main, deferreturn of
    # sync.(*Once).doSlow, and FuncIDWrapper (carried by runtime.deferreturn) of that Go version
    BASICS = {
        BASICS_1225: (0x470640, 0x470520, 0x470720, (18, 910), 237, 22),
        BASICS_1225_STRIPPED: (0x470640, 0x470520, 0x470720, (18, 910), 237, 22),
        BASICS_1271: (0x490FE0, 0x490EE0, 0x4910C0, (17, 1230), 214, 23),
    }

    def test_basics_func_fields(self):
        for path, (parse_addr, fib_addr, main_addr, runtime_main, do_slow_defer, wrapper_id) in self.BASICS.items():
            tab = _load(path)
            assert tab.go_version == (1, 20)
            assert tab.layout_version == (1, 20)
            f = _by_name(tab)

            # func parse(s string) (int, error): the string spills to 16 bytes, the results stay in registers
            parse = f["main.parse"]
            assert parse.addr == parse_addr
            assert parse.args == 16
            assert (parse.deferreturn, parse.func_id, parse.flag) == (0, 0, 0)
            assert parse.start_line == 59
            assert (parse.npcdata, parse.nfuncdata) == (4, 7)
            assert parse.pcsp and parse.pcfile and parse.pcln

            main = f["main.main"]
            assert (main.addr, main.args, main.start_line) == (main_addr, 0, 96)
            assert (main.npcdata, main.nfuncdata) == (2, 2)

            fib = f["main.fib"]  # func fib(n int) int
            assert (fib.addr, fib.args, fib.start_line) == (fib_addr, 8, 26)
            assert f["main.add"].args == 16  # func add(a, b int) int
            assert f["main.divmod"].args == 16  # func divmod(a, b int) (int, int)

            goexit = f["runtime.goexit"]
            assert (goexit.func_id, goexit.flag) == (8, GO_FUNC_FLAG_TOP_FRAME | GO_FUNC_FLAG_ASM)
            morestack = f["runtime.morestack"]
            assert (morestack.func_id, morestack.flag) == (13, GO_FUNC_FLAG_SP_WRITE | GO_FUNC_FLAG_ASM)
            memmove = f["runtime.memmove"]
            assert (memmove.flag, memmove.args, memmove.npcdata, memmove.nfuncdata) == (GO_FUNC_FLAG_ASM, 24, 0, 0)
            assert (f["runtime.gopanic"].func_id, f["runtime.gopanic"].args) == (10, 16)
            assert (f["runtime.main"].func_id, f["runtime.main"].deferreturn) == runtime_main
            assert f["sync.(*Once).doSlow"].deferreturn == do_slow_defer
            assert f["runtime.deferreturn"].func_id == wrapper_id

            # assembly bodies without a Go declaration have no known argument size
            assert f["indexbytebody"].args == -0x80000000
            assert all(func.args == -0x80000000 for func in tab.functions if func.args < 0)

    def test_basics_pcsp(self):
        fib_tail = {BASICS_1271: [(70, 8), (71, 0)]}
        main_tail = {BASICS_1271: [(470, 8), (471, 0)]}
        for path in self.BASICS:
            tab = _load(path)
            f = _by_name(tab)

            # main.fib: a 24-byte frame (locals=0x18, including the saved BP), torn down and rebuilt
            # around the tail of each recursive call
            fib = tab.pcsp(f["main.fib"])
            expected = [(0, 0), (7, 8), (14, 24), (24, 8), (25, 0), (26, 24)] + fib_tail.get(path, [(81, 8), (82, 0)])
            assert fib == expected
            assert fib[0] == (0, 0)
            assert max(delta for _, delta in fib) == 24

            parse = [(0, 0), (7, 8), (14, 24), (57, 8), (58, 0), (59, 24), (67, 8), (68, 0), (69, 24), (75, 8), (76, 0)]
            assert tab.pcsp(f["main.parse"]) == parse
            assert tab.pcsp(f["main.main"]) == [(0, 0), (16, 8), (26, 168)] + main_tail.get(path, [(482, 8), (483, 0)])
            assert tab.pcsp(f["main.add"]) == [(0, 0)]  # frameless leaf
            assert tab.pcsp(f["runtime.morestack"]) == [(0, 0)]

    def test_sp_delta(self):
        tab = _load(BASICS_1225)
        fib = _by_name(tab)["main.fib"]
        assert tab.sp_delta(fib, fib.addr) == 0
        assert tab.sp_delta(fib, fib.addr + 7) == 8
        assert tab.sp_delta(fib, fib.addr + 13) == 8
        assert tab.sp_delta(fib, fib.addr + 14) == 24
        assert tab.sp_delta(fib, fib.addr + 24) == 8
        assert tab.sp_delta(fib, fib.addr + 25) == 0
        assert tab.sp_delta(fib, fib.addr + 26) == 24
        assert tab.sp_delta(fib, fib.addr + 82) == 0
        assert tab.sp_delta(fib, fib.addr + fib.size - 1) == 0
        assert tab.sp_delta(fib, fib.addr - 1) is None
        assert tab.sp_delta(fib, fib.addr + fib.size) is None

    def test_basics_line_tables(self):
        tab = _load(BASICS_1225)
        f = _by_name(tab)
        fib = f["main.fib"]
        assert tab.pcln(fib) == [(0, 26), (14, 27), (20, 28), (26, 27), (31, 30), (83, 26)]
        assert tab.pcfile(fib) == [(0, "./basics.go")]
        assert tab.pcln(f["main.main"])[0] == (0, 96)
        assert tab.pcfile(f["main.main"]) == [(0, "./basics.go")]
        assert tab.pcln(f["runtime.goexit"]) == [(0, 1695), (1, 1696), (6, 1698)]
        assert tab.pcfile(f["runtime.goexit"]) == [(0, "runtime/asm_amd64.s")]

        # PCDATA_UnsafePoint=0, StackMapIndex=1, InlTreeIndex=2, ArgLiveIndex=3
        assert tab.pcdata(fib, 0) == [(0, -1), (4, -2), (6, -1), (83, -2), (93, -1)]
        assert tab.pcdata(fib, 1) == [(0, -1), (38, 0), (83, -1)]
        assert tab.pcdata(fib, 2) == []  # nothing inlined: offset 0
        assert tab.pcdata(fib, 3) == [(0, -1), (14, 1), (31, -1)]
        assert tab.pcdata(fib, 4) == []
        assert tab.pcdata(fib, -1) == []

    def test_stripped_binary(self):
        # stripping leaves the pclntab untouched; the functions only get registered as symbols
        plain = _load(BASICS_1225)
        ld = cle.Loader(BASICS_1225_STRIPPED, auto_load_libs=False)
        stripped = ld.main_object.gopclntab
        assert stripped.functions == plain.functions
        assert len([s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]) == 2017
        assert ld.find_symbol("main.parse").rebased_addr == 0x470640
        assert stripped.function_at(0x470640 + 3).name == "main.parse"

    def test_function_at(self):
        tab = _load(BASICS_1225)
        f = _by_name(tab)
        fib = f["main.fib"]
        assert tab.function_at(fib.addr) is fib
        assert tab.function_at(fib.addr + fib.size - 1) is fib
        assert tab.function_at(fib.addr + fib.size) is f["main.divmod"]
        assert tab.function_at(tab.functions[0].addr - 1) is None
        last = tab.functions[-1]
        assert tab.function_at(last.addr + last.size) is None

    def test_langdetect_go(self):
        tab = _load(LANGDETECT)
        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.args, main.start_line) == (0x4835C0, 0, 17)
        assert (main.npcdata, main.nfuncdata) == (3, 4)
        assert tab.pcsp(main) == [(0, 0), (11, 8), (18, 112), (201, 8), (202, 0)]
        assert tab.pcfile(main)[0] == (0, "/workspace/binaires/tests_src/language_detector/hello_go.go")
        assert (f["runtime.goexit"].func_id, f["runtime.goexit"].flag) == (8, 5)
        assert (f["runtime.morestack"].func_id, f["runtime.morestack"].flag) == (13, 6)
        assert f["sync.(*Once).doSlow"].deferreturn == 258

        assert all(func.start_line for func in tab.functions)
        assert sum(1 for func in tab.functions if func.deferreturn) == 8
        assert sum(func.npcdata for func in tab.functions) == 5168
        assert sum(func.nfuncdata for func in tab.functions) == 9220
        assert max(func.func_id for func in tab.functions) == 22
        assert {func.flag for func in tab.functions} == {0, 4, 5, 6, 7}

    def test_go118_layout(self):
        # go1.18/1.19: entryoff uint32 like 1.20, but no startLine field
        tab = _load(os.path.join(TEST_LOCATION, "aarch64", "langdetect_go_go1.18.10"))
        assert tab.go_version == (1, 18)
        assert tab.layout_version == (1, 18)
        assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (8, 4, 0x11000, 1384)
        assert all(func.start_line is None for func in tab.functions)
        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata) == (0x901D0, 0xF0, 0, 3, 4)
        assert tab.pcsp(main) == [(0, 0), (20, 128), (220, 0)]  # pc deltas scaled by min_lc
        assert (f["runtime.goexit"].func_id, f["runtime.goexit"].flag) == (7, 5)
        assert (f["runtime.morestack"].func_id, f["runtime.morestack"].flag) == (12, 6)
        assert (f["runtime.memmove"].flag, f["runtime.memmove"].args) == (GO_FUNC_FLAG_ASM, 24)
        assert (f["runtime.gopanic"].func_id, f["runtime.gopanic"].args) == (9, 16)
        assert tab.pcsp(f["runtime.gopanic"]) == [(0, 0), (20, 192), (1000, 0), (1004, 192), (1724, 0)]
        assert f["sync.(*Once).doSlow"].deferreturn == 340
        assert sum(1 for func in tab.functions if func.deferreturn) == 7
        assert sum(func.npcdata for func in tab.functions) == 4551
        assert sum(func.nfuncdata for func in tab.functions) == 7816

        tab = _load(os.path.join(TEST_LOCATION, "i386", "langdetect_go_go1.18.10"))
        assert tab.layout_version == (1, 18)
        assert (tab.ptr_size, tab.min_lc, len(tab.functions)) == (4, 1, 1430)
        f = _by_name(tab)
        assert (f["main.main"].addr, f["main.main"].args) == (0x80C5CA0, 0)
        assert tab.pcsp(f["main.main"]) == [(0, 0), (25, 64), (263, 0)]
        assert (f["runtime.gopanic"].args, f["runtime.memmove"].args) == (8, 12)
        assert f["sync.(*Once).doSlow"].deferreturn == 237

    def test_go117_layout(self):
        # go1.16/1.17: 7-word header without textStart, pointer-sized functab entries, entry uintptr
        path = os.path.join(TEST_LOCATION, "aarch64", "langdetect_go_go1.17.13")
        tab = _load(path)
        assert tab.go_version == (1, 16)
        assert tab.layout_version == (1, 16)
        assert (tab.ptr_size, tab.min_lc, len(tab.functions)) == (8, 4, 1320)
        assert tab.text_start == tab.functions[0].addr
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        assert all(func.size > 0 for func in tab.functions)
        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata) == (0x97050, 0x130, 0, 3, 4)
        assert main.start_line is None
        assert tab.pcsp(main) == [(0, 0), (20, 160), (280, 0)]
        assert (f["runtime.goexit"].func_id, f["runtime.goexit"].flag) == (7, GO_FUNC_FLAG_TOP_FRAME)
        assert (f["runtime.morestack"].func_id, f["runtime.morestack"].flag) == (13, GO_FUNC_FLAG_SP_WRITE)
        assert (f["runtime.gopanic"].func_id, f["runtime.gopanic"].args) == (9, 16)
        assert tab.pcsp(f["runtime.gopanic"]) == [(0, 0), (20, 224), (1092, 0), (1096, 224), (1960, 0)]
        assert (f["runtime.memmove"].args, f["runtime.memmove"].flag) == (24, 0)  # no FuncFlagAsm yet
        assert f["sync.(*Once).doSlow"].deferreturn == 344
        assert sum(1 for func in tab.functions if func.deferreturn) == 6
        assert sum(func.npcdata for func in tab.functions) == 3076
        assert sum(func.nfuncdata for func in tab.functions) == 6608

        tab = _load(os.path.join(TEST_LOCATION, "i386", "langdetect_go_go1.17.13"))
        assert tab.layout_version == (1, 16)
        assert (tab.ptr_size, tab.min_lc, len(tab.functions)) == (4, 1, 1407)
        f = _by_name(tab)
        assert (f["main.main"].addr, f["main.main"].args) == (0x80C3D90, 0)
        assert tab.pcsp(f["main.main"]) == [(0, 0), (25, 68), (265, 0)]
        assert (f["runtime.gopanic"].args, f["sync.(*Once).doSlow"].deferreturn) == (8, 221)

    def test_damaged_table_layout_inference(self):
        # with the magic clobbered, the record layout is picked by how the records pack
        tab = _load(DAMAGED_BINARY)
        assert tab.go_version is None
        assert tab.layout_version == (1, 20)
        assert all(func.flag <= 7 for func in tab.functions)
        assert max(func.func_id for func in tab.functions) == 23
        assert sum(1 for func in tab.functions if func.start_line) == 6077
        f = _by_name(tab)
        gomaxprocs = f["runtime.GOMAXPROCS"]
        assert (gomaxprocs.args, gomaxprocs.start_line, gomaxprocs.npcdata, gomaxprocs.nfuncdata) == (8, 70, 4, 7)
        assert tab.pcsp(gomaxprocs)[:3] == [(0, 0), (11, 8), (18, 48)]
        assert tab.pcfile(gomaxprocs)[0][1].endswith("/debug.go")  # the directory name was obfuscated
        assert tab.pcln(f["runtime.Caller"])[0] == (0, 309)

    def test_pcvalue_encoding(self):
        # (zigzag varint value delta, varint pc delta in units of min_lc)*, then a zero value delta;
        # the first value delta is relative to -1
        table = b"\0" + bytes([2, 7, 0x10, 7, 0x20, 10, 0x1F, 1, 0x80, 0x01, 0x81, 0x01, 0])
        tab = GoPclntab(0, 1, 8, 0, [], data=table, pctab_off=0, pcln_off=len(table))
        assert tab.pcvalue(0) == []  # offset 0 means "no table"
        assert tab.pcvalue(1) == [(0, 0), (7, 8), (14, 24), (24, 8), (25, 72)]
        tab = GoPclntab(0, 4, 8, 0, [], data=table, pctab_off=0, pcln_off=len(table))
        assert tab.pcvalue(1) == [(0, 0), (28, 8), (56, 24), (96, 8), (100, 72)]

        # garbage and truncated tables do not raise
        junk = b"\0" + b"\xff" * 16
        assert GoPclntab(0, 1, 8, 0, [], data=junk, pctab_off=0, pcln_off=len(junk)).pcvalue(1) == []
        cut = table[:5]
        assert GoPclntab(0, 1, 8, 0, [], data=cut, pctab_off=0, pcln_off=len(cut)).pcvalue(1) == [(0, 0), (7, 8)]


def _pcvalue(pairs):
    """
    Encode ``(pc delta, value)`` pairs the way the Go linker does (min_lc 1).
    """
    out = bytearray()
    val = -1
    for pc_delta, value in pairs:
        delta = value - val
        out += bytes([(delta << 1) & 0xFF if delta >= 0 else ((~delta << 1) | 1) & 0xFF, pc_delta])
        val = value
    return bytes(out + b"\0")


def _synthetic_pre116_table(tail="int32", ptr_size=8, magic=0xFFFFFFFB, slot4=(0, 0, 1)):
    """
    A well-formed 0xfffffffb table of three functions laid out like the Go 1.2 - 1.15 linkers do it:
    each _func is followed by its pcdata offsets, pointer-aligned funcdata, its name and then its
    pc-value tables. ``tail`` picks the 1.2 - 1.11 ``nfuncdata int32`` tail or the 1.12 - 1.15
    ``funcID u8, pad[2], nfuncdata u8`` one; ``slot4`` the values of the frame/funcID/deferreturn word.
    """
    ptr = "Q" if ptr_size == 8 else "I"
    funcs = [("main.main", 0x401000, 0, 2), ("main.fib", 0x401040, 16, 1), ("runtime.goexit", 0x401080, 0, 0)]
    nfunc = len(funcs)
    header = 8 + ptr_size
    functab_off = header
    filetab_ptr_off = functab_off + (2 * nfunc + 1) * ptr_size
    data = bytearray(filetab_ptr_off + 4)
    struct.pack_into("<IHBB", data, 0, magic, 0, 1, ptr_size)
    struct.pack_into(f"<{ptr}", data, 8, nfunc)

    def align():
        while len(data) % ptr_size:
            data.append(0)

    func_offs = []
    for (name, entry, args, nfuncdata), value in zip(funcs, slot4):
        align()
        func_offs.append(len(data))
        rec = struct.pack(f"<{ptr}", entry)
        fixed = len(rec) + 8 * 4
        end = func_offs[-1] + fixed + 4  # one pcdata offset
        if nfuncdata:
            end = (end + ptr_size - 1) & ~(ptr_size - 1)
            end += ptr_size * nfuncdata
        name_off = end
        pcsp_off = name_off + len(name) + 1
        pcsp = _pcvalue([(7, 0), (10, 8)])
        pcfile_off = pcsp_off + len(pcsp)
        pcfile = _pcvalue([(20, 1)])
        pcln_off = pcfile_off + len(pcfile)
        pcln = _pcvalue([(20, 10)])
        pcdata_off = pcln_off + len(pcln)
        pcdata = _pcvalue([(20, 3)])
        rec += struct.pack("<iiIIIII", name_off, args, value, pcsp_off, pcfile_off, pcln_off, 1)
        rec += struct.pack("<I", nfuncdata) if tail == "int32" else struct.pack("<BxxB", value, nfuncdata)
        rec += struct.pack("<I", pcdata_off)
        data += rec
        if nfuncdata:
            align()
            data += b"\0" * (ptr_size * nfuncdata)
        assert len(data) == end
        data += name.encode() + b"\0" + pcsp + pcfile + pcln + pcdata
    align()
    filetab_off = len(data)
    data += struct.pack("<II", 2, filetab_off + 8) + b"a.go\0"
    struct.pack_into("<I", data, filetab_ptr_off, filetab_off)
    entries = [entry for _, entry, _, _ in funcs] + [0x4010C0]
    for i, entry in enumerate(entries):
        struct.pack_into(f"<{ptr}", data, functab_off + 2 * i * ptr_size, entry)
    for i, off in enumerate(func_offs):
        struct.pack_into(f"<{ptr}", data, functab_off + (2 * i + 1) * ptr_size, off)
    return bytes(data)


class TestGo12Layout(unittest.TestCase):
    """
    The 0xfffffffb table of Go 1.2 - 1.9: the fourth _func word is the frame size (1.2 - 1.4) or the
    0x1234567 sentinel (1.5 - 1.9) and the record ends with ``nfuncdata int32``. There is no funcID,
    deferreturn, cuOffset or startLine; names, pc-value offsets and the filetab are relative to the
    table start. go1.4.3 and go1.9.7 builds of basics.go, cross-checked with debug/gosym.
    """

    def test_go143(self):
        path = _basics("go1.4.3")
        tab = _load(path)
        assert tab.magic == 0xFFFFFFFB
        assert tab.go_version == (1, 2)
        assert tab.layout_version == (1, 2)
        assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (8, 1, 0x400C00, 1096)
        assert tab.text_start == tab.functions[0].addr
        symtab = _symtab_functions(path)
        assert sum(1 for func in tab.functions if func.name in symtab.get(func.addr, ())) == 1083
        assert all(func.size > 0 for func in tab.functions)
        assert all(func.cu_offset is None and func.start_line is None for func in tab.functions)
        assert all(func.func_id == 0 and func.flag == 0 and func.deferreturn == 0 for func in tab.functions)

        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata) == (0x400F30, 0x2F0, 0, 1, 2)
        assert tab.pcsp(main) == [(0, 0), (34, 224), (726, 0), (727, 224)]
        assert tab.pcfile(main) == [(0, "/workspace/binaries/tests_src/go/basics.go")]
        assert tab.pcln(main)[:3] == [(0, 96), (34, 97), (43, 98)]
        fib = f["main.fib"]
        assert (fib.addr, fib.args) == (0x400C20, 16)  # stack ABI: n int plus the int result
        assert tab.pcsp(fib) == [(0, 0), (26, 24), (46, 0), (47, 24), (112, 0)]
        assert tab.pcln(fib) == [(0, 26), (31, 27), (37, 28), (47, 30)]
        assert tab.pcdata(fib, 0) == [(0, -1), (57, 0)]
        assert (f["main.add"].args, f["main.divmod"].args, f["main.parse"].args) == (24, 32, 40)
        assert (f["runtime.gopanic"].args, f["runtime.memmove"].args) == (16, 24)
        assert tab.pcfile(f["runtime.goexit"]) == [(0, "/usr/local/go/src/runtime/asm_amd64.s")]
        assert sum(1 for func in tab.functions if func.args < 0) == 25
        assert sum(func.nfuncdata for func in tab.functions) == 1417

    def test_go197(self):
        tab = _load(_basics("go1.9.7"))
        assert (tab.go_version, tab.layout_version) == ((1, 2), (1, 2))
        assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (8, 1, 0x401000, 1095)
        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata) == (0x45A770, 0x2C0, 0, 1, 2)
        assert tab.pcsp(main) == [(0, 0), (31, 192), (639, 0), (640, 192), (691, 0)]
        assert tab.pcln(main)[:2] == [(0, 96), (47, 98)]
        assert tab.pcfile(main) == [(0, "/workspace/binaries/tests_src/go/basics.go")]
        assert (f["main.fib"].addr, f["main.fib"].args) == (0x45A4B0, 16)
        assert tab.pcsp(f["main.fib"]) == [(0, 0), (19, 32), (54, 0), (55, 32), (120, 0)]
        assert tab.pcdata(f["main.fib"], 0) == [(0, -1), (63, 0), (121, -1)]
        assert tab.pcln(f["runtime.goexit"]) == [(0, 2337), (1, 2338), (6, 2340)]
        assert all(func.func_id == 0 and func.deferreturn == 0 for func in tab.functions)
        assert sum(func.npcdata for func in tab.functions) == 1279

    def test_stripped(self):
        for version, count in (("go1.4.3", 1096), ("go1.9.7", 1095)):
            ld = cle.Loader(_basics(version, stripped=True), auto_load_libs=False)
            tab = ld.main_object.gopclntab
            assert tab.functions == _load(_basics(version)).functions
            assert len([s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]) == count
            assert ld.find_symbol("main.fib") is not None


class TestGo110Layout(unittest.TestCase):
    """
    Go 1.10 - 1.11: still the 0xfffffffb table with the ``nfuncdata int32`` tail, but the retired
    frame word now carries funcID (a uint32). go1.10.8 builds; debug/gosym agrees on every field.
    """

    def test_basics(self):
        path = _basics("go1.10.8")
        tab = _load(path)
        assert tab.magic == 0xFFFFFFFB
        assert (tab.go_version, tab.layout_version) == ((1, 10), (1, 10))
        assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (8, 1, 0x401000, 1335)
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        assert len(symtab) == 1336  # plus one non-Go symbol
        assert all(func.cu_offset is None and func.start_line is None for func in tab.functions)
        assert all(func.deferreturn == 0 and func.flag == 0 for func in tab.functions)

        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata, main.func_id) == (
            0x45C5B0,
            0x2C0,
            0,
            1,
            2,
            0,
        )
        assert tab.pcsp(main) == [(0, 0), (31, 192), (639, 0), (640, 192), (691, 0)]
        assert tab.pcfile(main) == [(0, "/workspace/binaries/tests_src/go/basics.go")]
        assert tab.pcln(main)[:3] == [(0, 96), (47, 98), (76, 103)]
        fib = f["main.fib"]
        assert (fib.addr, fib.args) == (0x45C310, 16)
        assert tab.pcsp(fib) == [(0, 0), (19, 32), (54, 0), (55, 32), (120, 0)]
        assert tab.pcln(fib) == [(0, 26), (34, 27), (40, 28), (55, 30), (121, 26)]
        assert tab.pcdata(fib, 0) == [(0, -1), (63, 0), (121, -1)]
        assert (f["main.add"].args, f["main.divmod"].args, f["main.parse"].args) == (24, 32, 40)
        assert tab.pcsp(f["main.parse"]) == [(0, 0), (23, 48), (124, 0), (125, 48), (147, 0), (148, 48), (176, 0)]

        # objabi.FuncID of go1.10: goexit=1, morestack=4; gopanic has none yet
        assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id, f["runtime.gopanic"].func_id) == (1, 4, 0)
        assert f["runtime.main"].func_id == 0
        assert max(func.func_id for func in tab.functions) == 17
        assert tab.pcln(f["runtime.goexit"]) == [(0, 2361), (1, 2362), (6, 2364)]
        assert (f["runtime.memmove"].args, f["runtime.memmove"].nfuncdata) == (24, 0)
        assert sum(1 for func in tab.functions if func.args < 0) == 31
        assert (sum(func.npcdata for func in tab.functions), sum(func.nfuncdata for func in tab.functions)) == (
            1062,
            2511,
        )

    def test_stripped(self):
        ld = cle.Loader(_basics("go1.10.8", stripped=True), auto_load_libs=False)
        tab = ld.main_object.gopclntab
        assert tab.functions == _load(_basics("go1.10.8")).functions
        assert len([s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]) == 1335
        assert ld.find_symbol("main.parse").rebased_addr == 0x45C450

    def test_arm64(self):
        path = _langdetect("aarch64", "go1.10.8")
        tab = _load(path)
        assert (tab.layout_version, tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (
            (1, 10),
            8,
            4,
            0x11000,
            1756,
        )
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.nfuncdata) == (0x8D8B0, 0x110, 0, 2)
        assert tab.pcsp(main) == [(0, 0), (20, 128), (212, 0), (216, 128), (256, 0)]  # pc deltas scaled by min_lc
        assert tab.pcln(f["main.fibonacci"])[:2] == [(0, 10), (24, 11)]
        assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id) == (1, 4)
        assert tab.pcfile(f["runtime.goexit"]) == [(0, "/home/node/sdk/go1.10.8/src/runtime/asm_arm64.s")]

    def test_arm(self):
        tab = _load(_langdetect("armel", "go1.10.8"))
        assert (tab.layout_version, tab.ptr_size, tab.min_lc, len(tab.functions)) == ((1, 10), 4, 4, 1809)
        f = _by_name(tab)
        assert (f["main.main"].addr, f["main.main"].size, f["main.main"].args) == (0x94814, 0x10C, 0)
        assert tab.pcsp(f["main.main"]) == [(0, 0), (16, 60), (236, 0), (248, 60)]
        assert (f["main.fibonacci"].args, f["runtime.gopanic"].args, f["runtime.memmove"].args) == (8, 8, 12)
        assert tab.pcsp(f["main.fibonacci"]) == [(0, 0), (16, 16), (92, 0)]
        assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id) == (1, 4)

    def test_pe_in_text(self):
        # Go linkers before 1.12 give a PE no .rdata: the table sits in .text, where the magic scan
        # has to look when there is no read-only data section at all
        for arch, ptr_size, count, main_addr, main_size, rt_main in (
            ("i386", 4, 1793, 0x47E1B0, 0x120, 0x425DC0),
            ("x86_64", 8, 1804, 0x48E640, 0x150, 0x429A00),
        ):
            ld = cle.Loader(_langdetect(arch, "go1.10.8", "pe"), auto_load_libs=False)
            obj = ld.main_object
            tab = obj.gopclntab
            assert tab is not None
            assert ".rdata" not in obj.sections_map
            assert (tab.layout_version, tab.ptr_size, tab.min_lc, len(tab.functions)) == ((1, 10), ptr_size, 1, count)
            assert tab.text_start == 0x401000
            f = _by_name(tab)
            assert (f["main.main"].addr, f["main.main"].size, f["main.main"].args) == (main_addr, main_size, 0)
            assert tab.pcfile(f["main.main"])[0] == (
                0,
                "/workspace/binaries/tests_src/language_detector/langdetect_go.go",
            )
            assert tab.pcln(f["main.main"])[0] == (0, 17)
            assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id) == (1, 4)
            # the COFF symbols of these PEs are not functions, so every entry becomes a symbol
            assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == count
            assert ld.find_symbol("runtime.main").rebased_addr == rt_main

    def test_tail_inference(self):
        # same magic and header as 1.12 - 1.15: the record tail is told apart by where the name lands
        with open(_basics("go1.10.8"), "rb") as fp:
            data = ELFFile(fp).get_section_by_name(".gopclntab").data()
        n = struct.unpack_from("<Q", data, 8)[0]
        func_offs = struct.unpack_from(f"<{2 * n + 1}Q", data, 16)[1::2]
        assert _infer_packing(data, "<", 8, 0, func_offs, (_LAYOUT_GO112, _LAYOUT_GO110)) is _LAYOUT_GO110
        assert _infer_packing(data, "<", 8, 0, func_offs, (_LAYOUT_GO110, _LAYOUT_GO112)) is _LAYOUT_GO110

        with open(_basics("go1.15.15"), "rb") as fp:
            data = ELFFile(fp).get_section_by_name(".gopclntab").data()
        n = struct.unpack_from("<Q", data, 8)[0]
        func_offs = struct.unpack_from(f"<{2 * n + 1}Q", data, 16)[1::2]
        assert _infer_packing(data, "<", 8, 0, func_offs, (_LAYOUT_GO110, _LAYOUT_GO112)) is _LAYOUT_GO112

        # the go1.2 - 1.9 tail reads like the 1.10 one; the frame sentinel in slot 4 tells them apart
        with open(_basics("go1.9.7"), "rb") as fp:
            data = ELFFile(fp).get_section_by_name(".gopclntab").data()
        n = struct.unpack_from("<Q", data, 8)[0]
        func_offs = struct.unpack_from(f"<{2 * n + 1}Q", data, 16)[1::2]
        assert _infer_packing(data, "<", 8, 0, func_offs, (_LAYOUT_GO112, _LAYOUT_GO110)) is _LAYOUT_GO110
        assert struct.unpack_from("<I", data, func_offs[0] + 16)[0] == 0x1234567
        assert GoPclntab.parse(data).layout_version == (1, 2)

    def test_clobbered_magic(self):
        # the 1.2-style header is the last reading tried for an unknown magic
        with open(_basics("go1.10.8"), "rb") as fp:
            data = ELFFile(fp).get_section_by_name(".gopclntab").data()
        clobbered = b"\x12\x34\x56\x78" + data[4:]
        tab = GoPclntab.parse(clobbered, is_text_addr=lambda addr: 0x401000 <= addr < 0x480000)
        assert tab is not None
        assert tab.go_version is None
        assert tab.layout_version == (1, 10)
        assert tab.functions == GoPclntab.parse(data).functions


class TestGo112Layout(unittest.TestCase):
    """
    Go 1.12 - 1.15: the 0xfffffffb table with ``deferreturn`` in the fourth word and the
    ``funcID u8, pad[2], nfuncdata u8`` tail. go1.15.15 builds for ELF (amd64, 386), PE and Mach-O.
    """

    def test_basics(self):
        path = _basics("go1.15.15")
        tab = _load(path)
        assert tab.magic == 0xFFFFFFFB
        assert (tab.go_version, tab.layout_version) == ((1, 12), (1, 12))
        assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (8, 1, 0x401000, 1599)
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        assert all(func.cu_offset is None and func.start_line is None and func.flag == 0 for func in tab.functions)

        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata) == (0x475200, 0x300, 0, 2, 2)
        assert tab.pcsp(main) == [(0, 0), (31, 192), (679, 0), (680, 192), (727, 0)]
        assert tab.pcfile(main) == [(0, "/workspace/binaries/tests_src/go/basics.go")]
        assert tab.pcln(main)[:3] == [(0, 96), (47, 98), (75, 103)]
        fib = f["main.fib"]
        assert (fib.addr, fib.args) == (0x474F00, 16)
        assert tab.pcsp(fib) == [(0, 0), (19, 32), (54, 0), (55, 32), (125, 0)]
        assert tab.pcln(fib) == [(0, 26), (29, 27), (40, 28), (55, 30), (126, 26)]
        assert tab.pcdata(fib, 0) == [(0, -1), (13, -2), (15, -1), (126, -2), (133, -1)]
        assert tab.pcdata(fib, 1) == [(0, -1), (63, 0), (126, -1)]
        assert (f["main.add"].args, f["main.divmod"].args, f["main.parse"].args) == (24, 32, 40)

        # objabi.FuncID of go1.15: runtime_main=1, goexit=2, morestack=5, gopanic=18, wrapper=22
        assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id, f["runtime.gopanic"].func_id) == (2, 5, 18)
        assert (f["runtime.main"].func_id, f["runtime.main"].deferreturn) == (1, 785)
        assert f["sync.(*Once).doSlow"].deferreturn == 256
        assert max(func.func_id for func in tab.functions) == 22
        assert sum(1 for func in tab.functions if func.deferreturn) == 4
        assert (sum(func.npcdata for func in tab.functions), sum(func.nfuncdata for func in tab.functions)) == (
            2652,
            3227,
        )
        assert sum(1 for func in tab.functions if func.args < 0) == 38

    def test_stripped(self):
        ld = cle.Loader(_basics("go1.15.15", stripped=True), auto_load_libs=False)
        tab = ld.main_object.gopclntab
        assert tab.functions == _load(_basics("go1.15.15")).functions
        assert len([s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]) == 1599

    def test_386(self):
        path = _langdetect("i386", "go1.15.15")
        tab = _load(path)
        assert (tab.layout_version, tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (
            (1, 12),
            4,
            1,
            0x8049000,
            1809,
        )
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata) == (0x80CF5D0, 0x120, 0, 3, 5)
        assert tab.pcsp(main) == [(0, 0), (25, 68), (232, 0), (233, 68), (277, 0)]
        # an inlined fmt call switches the file in the middle of main
        assert [file for _, file in tab.pcfile(main)] == [
            "/workspace/binaries/tests_src/language_detector/langdetect_go.go",
            "/home/node/sdk/go1.15.15/src/fmt/print.go",
            "/workspace/binaries/tests_src/language_detector/langdetect_go.go",
        ]
        assert (f["main.fibonacci"].args, f["runtime.gopanic"].args, f["runtime.memmove"].args) == (8, 8, 12)
        assert (f["runtime.main"].func_id, f["runtime.main"].deferreturn) == (1, 841)
        assert f["sync.(*Once).doSlow"].deferreturn == 225

    def test_pe(self):
        ld = cle.Loader(_langdetect("x86_64", "go1.15.15", "pe"), auto_load_libs=False)
        obj = ld.main_object
        tab = obj.gopclntab
        assert tab is not None
        assert ".rdata" in obj.sections_map and ".gopclntab" not in obj.sections_map
        assert (tab.layout_version, tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (
            (1, 12),
            8,
            1,
            0x401000,
            1799,
        )
        f = _by_name(tab)
        assert (f["main.main"].addr, f["main.main"].size, f["main.main"].args) == (0x4A8B80, 0x160, 0)
        assert tab.pcsp(f["main.main"]) == [(0, 0), (38, 144), (287, 0), (289, 144), (336, 0)]
        assert (f["runtime.goexit"].func_id, f["runtime.main"].deferreturn, f["sync.(*Once).doSlow"].deferreturn) == (
            2,
            800,
            293,
        )
        assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == 1799
        assert ld.find_symbol("runtime.main").rebased_addr == 0x437FA0

    def test_macho(self):
        ld = cle.Loader(_langdetect("x86_64", "go1.15.15", "macho"), auto_load_libs=False)
        obj = ld.main_object
        assert isinstance(obj, cle.MachO)
        tab = obj.gopclntab
        assert tab is not None
        assert "__TEXT,__gopclntab" in obj.sections_map
        assert (tab.layout_version, tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (
            (1, 12),
            8,
            1,
            0x1001000,
            1919,
        )
        f = _by_name(tab)
        assert (f["main.main"].addr, f["main.main"].size, f["main.main"].args) == (0x10AA480, 0x160, 0)
        assert tab.pcsp(f["main.main"]) == [(0, 0), (31, 144), (282, 0), (283, 144), (330, 0)]
        assert tab.pcln(f["main.fibonacci"])[:2] == [(0, 10), (29, 11)]
        assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id, f["runtime.main"].deferreturn) == (
            2,
            5,
            849,
        )
        assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == 1919
        assert obj.get_symbol("runtime.main")[0].rebased_addr == 0x1033FA0

    def test_synthetic_table(self):
        tab = GoPclntab.parse(_synthetic_pre116_table("bytes", slot4=(0, 0, 2)))
        assert tab is not None
        assert (tab.go_version, tab.layout_version, tab.ptr_size, tab.text_start) == ((1, 12), (1, 12), 8, 0x401000)
        assert [(f.name, f.addr, f.size, f.args, f.nfuncdata, f.func_id) for f in tab.functions] == [
            ("main.main", 0x401000, 0x40, 0, 2, 0),
            ("main.fib", 0x401040, 0x40, 16, 1, 0),
            ("runtime.goexit", 0x401080, 0x40, 0, 0, 2),
        ]
        for func in tab.functions:
            assert tab.pcsp(func) == [(0, 0), (7, 8)]
            assert tab.pcfile(func) == [(0, "a.go")]
            assert tab.pcln(func) == [(0, 10)]
            assert tab.pcdata(func, 0) == [(0, 3)]
            assert tab.pcdata(func, 1) == []

        # with the int32 tail the same values mean funcID in slot 4 (go1.10 - 1.11)
        tab = GoPclntab.parse(_synthetic_pre116_table("int32", slot4=(0, 0, 2)))
        assert (tab.go_version, tab.layout_version) == ((1, 10), (1, 10))
        assert [(f.name, f.nfuncdata, f.func_id, f.deferreturn) for f in tab.functions] == [
            ("main.main", 2, 0, 0),
            ("main.fib", 1, 0, 0),
            ("runtime.goexit", 0, 2, 0),
        ]
        # and frame sizes there mean go1.2 - 1.9 (no funcID at all)
        tab = GoPclntab.parse(_synthetic_pre116_table("int32", slot4=(0x100, 0x20, 0)))
        assert (tab.go_version, tab.layout_version) == ((1, 2), (1, 2))
        assert all(func.func_id == 0 for func in tab.functions)
        tab = GoPclntab.parse(_synthetic_pre116_table("int32", slot4=(0x1234567, 0x1234567, 0x1234567)))
        assert tab.layout_version == (1, 2)

        # 32-bit pointers
        tab = GoPclntab.parse(_synthetic_pre116_table("bytes", ptr_size=4, slot4=(0, 0, 2)))
        assert (tab.layout_version, tab.ptr_size) == ((1, 12), 4)
        assert [f.addr for f in tab.functions] == [0x401000, 0x401040, 0x401080]
        assert tab.pcsp(tab.functions[1]) == [(0, 0), (7, 8)]

    def test_synthetic_table_rejects_bad_header_fields(self):
        data = _synthetic_pre116_table("bytes", slot4=(0, 0, 2))
        assert GoPclntab.parse(data) is not None

        def mutate(offset, value, fmt="<Q"):
            return data[:offset] + struct.pack(fmt, value) + data[offset + struct.calcsize(fmt) :]

        assert GoPclntab.parse(mutate(7, 2, "<B")) is None  # ptrSize
        assert GoPclntab.parse(mutate(6, 3, "<B")) is None  # minLC
        assert GoPclntab.parse(mutate(4, 1, "<H")) is None  # padding
        assert GoPclntab.parse(mutate(8, 0)) is None  # nfunc
        assert GoPclntab.parse(mutate(8, 1 << 40)) is None  # nfunc
        assert GoPclntab.parse(mutate(8, 1000)) is None  # functab past the end
        assert GoPclntab.parse(mutate(16 + 2 * 8, 0x401000)) is None  # non-monotonic entries
        assert GoPclntab.parse(mutate(16 + 7 * 8, 0)) is None  # filetab offset before the functab
        assert GoPclntab.parse(mutate(16 + 7 * 8, len(data), "<I")) is None  # filetab past the end
        assert GoPclntab.parse(mutate(16 + 7 * 8, 16 + 7 * 8 + 4, "<I")) is None  # nfiles (reads a _func)
        assert GoPclntab.parse(mutate(16 + 3 * 8, len(data))) is None  # funcoff past the end
        assert GoPclntab.parse(mutate(16 + 3 * 8 + 8, 1 << 20, "<i")) is None  # nameoff past the end

        # a clobbered magic still parses through the structural checks
        tab = GoPclntab.parse(mutate(0, 0xDEADBEEF, "<I"), is_text_addr=lambda addr: addr >= 0x401000)
        assert tab is not None and tab.go_version is None and tab.layout_version == (1, 12)
        assert GoPclntab.parse(mutate(0, 0xDEADBEEF, "<I"), is_text_addr=lambda addr: False) is None

    def test_rejects_non_tables_with_the_magic(self):
        # what the data-section scan has to turn down: the magic bytes followed by anything else
        header = b"\xfb\xff\xff\xff\0\0\x01\x08"
        assert GoPclntab.parse(header) is None
        assert GoPclntab.parse(header + b"\0" * 4096) is None
        assert GoPclntab.parse(header + b"\xff" * 4096) is None
        assert GoPclntab.parse(header + os.urandom(4096)) is None
        assert GoPclntab.parse(header + struct.pack("<Q", 1) + os.urandom(4096)) is None
        assert GoPclntab.parse(header + struct.pack("<QQQQI", 2, 0x1000, 32, 0x2000, 100) + b"\0" * 4096) is None


class TestGo116Layout(unittest.TestCase):
    """
    The real Go 1.16 table (0xfffffffa, cutab/filetab/pctab sub-tables, pointer-sized functab
    entries, no flag byte: the byte 1.17 turns into ``flag`` is still padding). go1.16.15 builds;
    the existing go1.17.13 fixtures cover the 1.17 flavour of the same layout.
    """

    def test_basics(self):
        path = _basics("go1.16.15")
        tab = _load(path)
        assert tab.magic == 0xFFFFFFFA
        assert (tab.go_version, tab.layout_version) == ((1, 16), (1, 16))
        assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (8, 1, 0x401000, 1610)
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        assert all(func.start_line is None for func in tab.functions)
        assert all(func.flag == 0 for func in tab.functions)  # no FuncFlag before 1.17
        assert all(func.cu_offset is not None for func in tab.functions)

        f = _by_name(tab)
        main = f["main.main"]
        assert (main.addr, main.size, main.args, main.npcdata, main.nfuncdata, main.cu_offset) == (
            0x476400,
            0x300,
            0,
            2,
            2,
            307,
        )
        assert tab.pcsp(main) == [(0, 0), (31, 192), (679, 0), (680, 192), (727, 0)]
        assert tab.pcfile(main) == [(0, "/workspace/binaries/tests_src/go/basics.go")]
        assert tab.pcln(main)[:3] == [(0, 96), (47, 98), (75, 103)]
        fib = f["main.fib"]
        assert (fib.addr, fib.args) == (0x476100, 16)
        assert tab.pcsp(fib) == [(0, 0), (19, 32), (54, 0), (55, 32), (125, 0)]
        assert tab.pcdata(fib, 1) == [(0, -1), (63, 0), (126, -1)]
        assert (f["main.add"].args, f["main.divmod"].args, f["main.parse"].args) == (24, 32, 40)
        assert tab.pcsp(f["main.parse"]) == [(0, 0), (23, 48), (127, 0), (129, 48), (151, 0), (152, 48), (180, 0)]
        assert (f["runtime.goexit"].func_id, f["runtime.morestack"].func_id, f["runtime.gopanic"].func_id) == (2, 5, 18)
        assert (f["runtime.main"].func_id, f["runtime.main"].deferreturn) == (1, 864)
        assert f["sync.(*Once).doSlow"].deferreturn == 256
        assert tab.pcfile(f["runtime.goexit"]) == [(0, "/home/node/sdk/go1.16.15/src/runtime/asm_amd64.s")]
        assert sum(1 for func in tab.functions if func.deferreturn) == 4
        assert (sum(func.npcdata for func in tab.functions), sum(func.nfuncdata for func in tab.functions)) == (
            2678,
            3138,
        )

    def test_stripped(self):
        ld = cle.Loader(_basics("go1.16.15", stripped=True), auto_load_libs=False)
        assert ld.main_object.gopclntab.functions == _load(_basics("go1.16.15")).functions
        assert len([s for s in ld.main_object.symbols if isinstance(s, cle.GoSymbol)]) == 1610

    def test_arm64(self):
        path = _langdetect("aarch64", "go1.16.15")
        tab = _load(path)
        assert (tab.layout_version, tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (
            (1, 16),
            8,
            4,
            0x11000,
            1442,
        )
        symtab = _symtab_functions(path)
        assert all(func.name in symtab.get(func.addr, ()) for func in tab.functions)
        f = _by_name(tab)
        assert (f["main.main"].addr, f["main.main"].size, f["main.main"].cu_offset) == (0x9ECC0, 0x130, 424)
        assert tab.pcsp(f["main.main"]) == [(0, 0), (20, 160), (236, 0), (240, 160), (284, 0)]
        assert tab.pcsp(f["main.fibonacci"]) == [(0, 0), (20, 48), (52, 0), (56, 48), (116, 0)]
        assert (f["runtime.main"].func_id, f["runtime.main"].deferreturn) == (1, 972)
        assert tab.pcfile(f["runtime.goexit"]) == [(0, "/home/node/sdk/go1.16.15/src/runtime/asm_arm64.s")]

    def test_pe(self):
        for arch, ptr_size, count, main_addr, main_size, cu, rt_main in (
            ("i386", 4, 1532, 0x492620, 0x120, 410, 0x4322E0),
            ("x86_64", 8, 1489, 0x4AA960, 0x160, 438, 0x4385A0),
        ):
            ld = cle.Loader(_langdetect(arch, "go1.16.15", "pe"), auto_load_libs=False)
            obj = ld.main_object
            tab = obj.gopclntab
            assert tab is not None
            assert ".rdata" in obj.sections_map
            assert (tab.layout_version, tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (
                (1, 16),
                ptr_size,
                1,
                0x401000,
                count,
            )
            f = _by_name(tab)
            assert (f["main.main"].addr, f["main.main"].size, f["main.main"].cu_offset) == (main_addr, main_size, cu)
            assert tab.pcfile(f["main.main"])[0] == (
                0,
                "/workspace/binaries/tests_src/language_detector/langdetect_go.go",
            )
            assert (f["runtime.goexit"].func_id, f["runtime.goexit"].flag) == (2, 0)
            assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == count
            assert ld.find_symbol("runtime.main").rebased_addr == rt_main


class TestGo117AndGo118PE(unittest.TestCase):
    """
    The 1.16-layout (go1.17.13) and 1.18-layout PE fixtures, found by magic in .rdata.
    """

    def test_go117_pe(self):
        for arch, ptr_size, min_lc, count, text, main_addr, main_size, rt_main in (
            ("i386", 4, 1, 1429, 0x401000, 0x488100, 0x114, 0x433640),
            ("aarch64", 8, 4, 1337, 0x100001000, 0x100096A50, 0x130, 0x100036430),
        ):
            ld = cle.Loader(_langdetect(arch, "go1.17.13", "pe"), auto_load_libs=False)
            obj = ld.main_object
            tab = obj.gopclntab
            assert tab is not None
            assert (tab.go_version, tab.layout_version) == ((1, 16), (1, 16))
            assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (ptr_size, min_lc, text, count)
            assert tab.text_start == tab.functions[0].addr
            f = _by_name(tab)
            assert (f["main.main"].addr, f["main.main"].size, f["main.main"].args) == (main_addr, main_size, 0)
            assert tab.pcln(f["main.main"])[0] == (0, 17)
            assert (f["runtime.goexit"].func_id, f["runtime.goexit"].flag) == (7, GO_FUNC_FLAG_TOP_FRAME)
            assert (f["runtime.morestack"].func_id, f["runtime.morestack"].flag) == (13, GO_FUNC_FLAG_SP_WRITE)
            assert (f["runtime.main"].func_id, f["runtime.gopanic"].func_id) == (18, 9)
            assert {func.flag for func in tab.functions} == {0, 1, 2, 3}
            assert all(func.start_line is None for func in tab.functions)
            assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == count
            assert ld.find_symbol("runtime.main").rebased_addr == rt_main

    def test_go118_pe(self):
        for arch, ptr_size, min_lc, count, text, main_addr, main_size, pcsp, rt_main in (
            ("i386", 4, 1, 1450, 0x401000, 0x489630, 0x112, [(0, 0), (25, 64), (263, 0)], 0x434530),
            ("aarch64", 8, 4, 1413, 0x100001000, 0x10008EEA0, 0xF0, [(0, 0), (20, 128), (220, 0)], 0x1000341C0),
        ):
            ld = cle.Loader(_langdetect(arch, "go1.18.10", "pe"), auto_load_libs=False)
            obj = ld.main_object
            tab = obj.gopclntab
            assert tab is not None
            assert (tab.go_version, tab.layout_version) == ((1, 18), (1, 18))
            assert (tab.ptr_size, tab.min_lc, tab.text_start, len(tab.functions)) == (ptr_size, min_lc, text, count)
            f = _by_name(tab)
            assert (f["main.main"].addr, f["main.main"].size, f["main.main"].args) == (main_addr, main_size, 0)
            assert tab.pcsp(f["main.main"]) == pcsp
            assert (f["runtime.goexit"].func_id, f["runtime.goexit"].flag) == (
                7,
                GO_FUNC_FLAG_TOP_FRAME | GO_FUNC_FLAG_ASM,
            )
            assert (f["runtime.morestack"].func_id, f["runtime.morestack"].flag) == (
                12,
                GO_FUNC_FLAG_SP_WRITE | GO_FUNC_FLAG_ASM,
            )
            assert f["runtime.memmove"].flag == GO_FUNC_FLAG_ASM
            assert (f["runtime.main"].func_id, f["runtime.gopanic"].func_id) == (17, 9)
            assert all(func.start_line is None for func in tab.functions)
            assert len([s for s in obj.symbols if isinstance(s, cle.GoSymbol)]) == count
            assert ld.find_symbol("runtime.main").rebased_addr == rt_main


if __name__ == "__main__":
    unittest.main()
