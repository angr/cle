from __future__ import annotations

import os
import pickle
import unittest

import cle
from cle.backends.elf.relocation.ppc64 import R_PPC64_JMP_SLOT
from cle.backends.externs import ExternObject
from cle.backends.symbol import SymbolType

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_f_finale_extern_size_hints():
    path = os.path.join(TESTS_BASE, "tests", "x86_64", "f_finale.o")
    ld = cle.Loader(path, auto_load_libs=False)
    obj = ld.main_object

    assert obj.is_relocatable  # type: ignore[attr-defined]
    assert hasattr(obj, "extern_size_hints")

    # mobjinfo: max addend is 52
    # min_size = 52 + 8 = 60
    assert obj.extern_size_hints["mobjinfo"] == 60  # type: ignore[attr-defined]

    mobjinfo = None
    for sym in ld.symbols:
        if sym.is_extern and sym.name == "mobjinfo":
            mobjinfo = sym
            break

    assert mobjinfo is not None
    assert mobjinfo.size == 60

    # Find the next symbol after mobjinfo
    next_sym = None
    for sym in ld.symbols:
        if sym.is_extern and sym.rebased_addr > mobjinfo.rebased_addr:
            if next_sym is None or sym.rebased_addr < next_sym.rebased_addr:
                next_sym = sym

    # Verify no overlap: mobjinfo end <= next symbol start
    assert next_sym is not None
    assert mobjinfo.rebased_addr + mobjinfo.size <= next_sym.rebased_addr


def test_ppc64_abiv1_untyped_function_import():
    """An imported function left STT_NOTYPE still needs an ELFv1 function descriptor.

    A jump slot on PowerPC64 ELFv1 holds a whole descriptor rather than an address, so an
    unresolved import needs one however the symbol table typed it. Deciding that from the
    declared type gives an untyped import a pointer-sized slot instead, and the descriptor copy
    then reads past it.
    """
    pristine = os.path.join(TESTS_BASE, "tests", "ppc64", "fauxware")
    untyped = os.path.join(TESTS_BASE, "tests", "ppc64", "fauxware_notype_import")

    def jump_slots(path):
        """The object, and each of its jump slots paired with the symbol it names."""
        obj = cle.Loader(path, auto_load_libs=False).main_object
        slots = []
        for reloc in obj.relocs:
            symbol = reloc.symbol
            if isinstance(reloc, R_PPC64_JMP_SLOT) and symbol is not None:
                slots.append((symbol, reloc))
        return obj, slots

    def descriptors(path):
        obj, slots = jump_slots(path)
        return {
            symbol.name: tuple(obj.memory.unpack_word(reloc.relative_addr + offset) for offset in (0, 8, 16))
            for symbol, reloc in slots
        }

    # the derived fixture has to still carry the shape, or this test proves nothing
    _, slots = jump_slots(untyped)
    assert {s.name for s, _ in slots if s.type is not SymbolType.TYPE_FUNCTION} == {"puts", "exit"}

    expected = descriptors(pristine)
    assert expected, "the pristine fixture has no jump slots to compare"
    assert descriptors(untyped) == expected


class TestSimDataExternTypes(unittest.TestCase):
    """Test that untyped extern requests use definitive SimData types."""

    def test_untyped_imports_adopt_simdata_type(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")

        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            ld = cle.Loader(path, auto_load_libs=False)

        for name in ("stdin", "stdout", "stderr", "optind", "optarg"):
            import_symbol = ld.main_object.get_symbol(name)
            self.assertIsNotNone(import_symbol)
            assert import_symbol is not None
            extern_symbol = import_symbol.resolvedby
            self.assertIsNotNone(extern_symbol)
            assert extern_symbol is not None
            self.assertIs(extern_symbol.type, SymbolType.TYPE_OBJECT)
            self.assertIs(extern_symbol._type, SymbolType.TYPE_OBJECT)

    def test_untyped_tls_simdata_uses_tls_storage(self):
        path = os.path.join(
            TESTS_BASE,
            "tests_src",
            "i2c_master_read-nucleol152re",
            "mbed",
            "TARGET_NUCLEO_L152RE",
            "TOOLCHAIN_GCC_ARM",
            "mbed_retarget.o",
        )
        ld = cle.Loader(path, auto_load_libs=False)

        import_symbol = ld.main_object.get_symbol("errno")
        self.assertIsNotNone(import_symbol)
        assert import_symbol is not None
        self.assertIs(import_symbol.type, SymbolType.TYPE_NONE)

        errno = import_symbol.resolvedby
        self.assertIsNotNone(errno)
        assert errno is not None
        self.assertIsInstance(errno.owner, ExternObject)
        owner = errno.owner
        assert isinstance(owner, ExternObject)

        self.assertIs(errno.type, SymbolType.TYPE_TLS_OBJECT)
        self.assertIs(errno._type, SymbolType.TYPE_TLS_OBJECT)
        self.assertEqual(errno.relative_addr, 0)
        self.assertEqual(owner.tls_next_addr, errno.size)
        self.assertEqual(owner.tls_data_size, errno.size)
        self.assertEqual(owner.tls_block_size, errno.size)
        self.assertTrue(owner.tls_used)
        self.assertIn(owner, ld.tls.modules)
        self.assertIsNotNone(owner.tls_module_id)
        self.assertIsNotNone(getattr(owner, "tls_block_offset", None))

    def test_definite_simdata_type_conflict_still_warns(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)
        root = ld.extern_object

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            progname = root.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            repeated = root.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertIs(repeated, progname)
        self.assertIs(progname.type, SymbolType.TYPE_OBJECT)
        # SimData.type describes the implementation, while _type retains the caller's definite request.
        self.assertIs(progname._type, SymbolType.TYPE_FUNCTION)
        self.assertIsInstance(progname.owner, ExternObject)
        owner = progname.owner
        assert isinstance(owner, ExternObject)
        self.assertIsNot(owner, root)
        self.assertEqual(owner.tls_next_addr, 0)
        assert owner.tls_data_start is not None
        self.assertGreaterEqual(progname.relative_addr, owner.tls_data_start + owner.tls_data_size)
        self.assertLessEqual(progname.relative_addr + progname.size, owner.next_addr)

    def test_cached_simdata_validates_later_definite_conflict(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)

        progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_NONE)
        self.assertIsInstance(progname.owner, ExternObject)
        owner = progname.owner
        assert isinstance(owner, ExternObject)
        layout = (
            progname.relative_addr,
            progname.size,
            owner.next_addr,
            owner.tls_next_addr,
            len(owner.symbols),
            len(ld.all_objects),
        )

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            conflicting = owner.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            repeated = owner.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
            repeated_from_root = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertIs(conflicting, progname)
        self.assertIs(repeated, progname)
        self.assertIs(repeated_from_root, progname)
        self.assertIs(progname.type, SymbolType.TYPE_OBJECT)
        self.assertIs(progname._type, SymbolType.TYPE_OBJECT)
        self.assertEqual(
            (
                progname.relative_addr,
                progname.size,
                owner.next_addr,
                owner.tls_next_addr,
                len(owner.symbols),
                len(ld.all_objects),
            ),
            layout,
        )

    def test_dynamic_load_simdata_conflicts_are_per_symbol(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "decompiler", "sort.o")
        ld = cle.Loader(path, auto_load_libs=False)

        old_import = ld.main_object.get_symbol("stdout")
        self.assertIsNotNone(old_import)
        assert old_import is not None
        old_stdout = old_import.resolvedby
        self.assertIsNotNone(old_stdout)
        assert old_stdout is not None
        old_progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_NONE)

        with open(path, "rb") as binary:
            loaded = ld.dynamic_load(binary)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        loaded_elf = next(obj for obj in loaded if isinstance(obj, cle.ELF))
        new_import = loaded_elf.get_symbol("stdout")
        self.assertIsNotNone(new_import)
        assert new_import is not None
        new_stdout = new_import.resolvedby
        self.assertIsNotNone(new_stdout)
        assert new_stdout is not None
        self.assertIsNot(new_stdout, old_stdout)
        self.assertIsInstance(old_stdout.owner, ExternObject)
        old_owner = old_stdout.owner
        assert isinstance(old_owner, ExternObject)
        self.assertIsInstance(new_stdout.owner, ExternObject)
        new_owner = new_stdout.owner
        assert isinstance(new_owner, ExternObject)

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            found_progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        self.assertIs(found_progname, old_progname)

        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            old_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)
            new_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 2)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            old_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)
            new_owner.make_extern("stdout", sym_type=SymbolType.TYPE_FUNCTION)

    def test_cached_simdata_conflict_survives_legacy_pickle(self):
        path = os.path.join(TESTS_BASE, "tests", "x86_64", "fauxware")
        ld = cle.Loader(path, auto_load_libs=False)
        progname = ld.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_NONE)
        self.assertFalse(hasattr(progname, "_warned_symbol_type_mismatches"))

        restored = pickle.loads(pickle.dumps(ld))
        with self.assertLogs("cle.backends.externs", level="WARNING") as logs:
            cached = restored.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)
        self.assertEqual(sum("Symbol type mismatch" in message for message in logs.output), 1)
        with self.assertNoLogs("cle.backends.externs", level="WARNING"):
            repeated = restored.extern_object.make_extern("__progname", sym_type=SymbolType.TYPE_FUNCTION)

        self.assertIs(repeated, cached)
        self.assertIs(cached.type, SymbolType.TYPE_OBJECT)
        self.assertIs(cached._type, SymbolType.TYPE_OBJECT)


if __name__ == "__main__":
    unittest.main()
