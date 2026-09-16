from __future__ import annotations

import os
import struct
import unittest

from elftools.elf.elffile import ELFFile

import cle
from cle.backends.gopclntab import GO_FUNC_FLAG_ASM, GO_FUNC_FLAG_SP_WRITE, GO_FUNC_FLAG_TOP_FRAME, GoPclntab

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


if __name__ == "__main__":
    unittest.main()
