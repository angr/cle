#!/usr/bin/env python

import logging
from pathlib import Path

import cle
from cle import MachO

TEST_BASE = Path(__file__).resolve().parent.parent.parent / "binaries" / "tests" / "aarch64" / "macho_lib_loading"


def test_library_15():
    """
    Test some basics about loading any kind of library
    :return:
    """

    ld = cle.Loader(TEST_BASE / "FrameWorkApp.app_15" / "Frameworks" / "dynamicLibrary.framework" / "dynamicLibrary")
    lib = ld.main_object
    assert isinstance(lib, MachO)
    # The base address should be 0 until full rebasing support is implemented
    # because the rebase blob isn't parsed yet, some internal pointers aren't rebased from their relative values
    # and only work out correctly if the library is loaded at 0
    assert ld.main_object.min_addr == 0


def test_library_14():
    """
    Test some basics about loading any kind of library
    :return:
    """
    ld = cle.Loader(TEST_BASE / "FrameWorkApp.app_14" / "Frameworks" / "dynamicLibrary.framework" / "dynamicLibrary")
    lib = ld.main_object
    assert isinstance(lib, MachO)
    # The base address should be 0 until full rebasing support is implemented
    # because the rebase blob isn't parsed yet, some internal pointers aren't rebased from their relative values
    # and only work out correctly if the library is loaded at 0
    assert ld.main_object.min_addr == 0


def test_framework_ios15():
    """
    Currently library loading for Mach-O is only supported via force_load_libs, auto_load_libs is ignored
    The Mach-O logic to resolve the path of a library is not implemented yet, because it is different and
    more complicated than ELF/PE
    :return:
    """
    ld = cle.Loader(
        TEST_BASE / "FrameWorkApp.app_15" / "FrameWorkApp",
        force_load_libs=(
            TEST_BASE / "FrameWorkApp.app_15" / "Frameworks" / "dynamicLibrary.framework" / "dynamicLibrary",
        ),
    )

    assert isinstance(ld.main_object, MachO)
    main = ld.main_object
    assert main.min_addr == 0x100000000

    _lib = ld.shared_objects["dynamicLibrary"]
    assert isinstance(_lib, MachO)
    lib = _lib

    assert lib.mapped_base != 0

    shared_symbols = ["_OBJC_CLASS_$_api"]

    assert {s.name for s in ld.main_object.resolved_imports if not s.resolvedby.is_extern} == set(shared_symbols)
    for s in shared_symbols:
        assert s in lib.exports_by_name
        assert s in main.imports

        reloc = main.imports[s]
        assert reloc.resolvedby.owner is not ld.extern_object
        target = ld.memory.unpack_word(reloc.rebased_addr)
        assert target >= 2**32, "Target address is not rebased"
        target_symbol = ld.find_symbol(target)
        assert target_symbol is not None
        assert target_symbol.name == s, "Target symbol is not the expected one"


def test_framework_ios14():
    ld = cle.Loader(
        TEST_BASE / "FrameWorkApp.app_14" / "FrameWorkApp",
        force_load_libs=(
            TEST_BASE / "FrameWorkApp.app_14" / "Frameworks" / "dynamicLibrary.framework" / "dynamicLibrary",
        ),
    )

    assert isinstance(ld.main_object, MachO)
    main = ld.main_object
    assert main.min_addr == 0x100000000
    _lib = ld.shared_objects["dynamicLibrary"]
    assert isinstance(_lib, MachO)
    lib = _lib

    assert lib.mapped_base != 0

    shared_symbols = ["_OBJC_CLASS_$_api"]

    assert {s.name for s in ld.main_object.resolved_imports if not s.resolvedby.is_extern} == set(shared_symbols)
    for s in shared_symbols:
        assert s in lib.exports_by_name
        assert s in main.imports

        reloc = main.imports[s]
        assert reloc.resolvedby.owner is not ld.extern_object
        target = ld.memory.unpack_word(reloc.rebased_addr)
        assert target >= 2**32, "Target address is not rebased"
        target_symbol = ld.find_symbol(target)
        assert target_symbol is not None
        assert target_symbol.name == s, "Target symbol is not the expected one"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_library_14()
    test_library_15()
    test_framework_ios14()
    test_framework_ios15()
