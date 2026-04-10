from __future__ import annotations

import os

import archinfo
import pytest

import cle
from cle import MachO, Universal2

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
FATBIN = os.path.join(TEST_BASE, "tests", "multi_arch", "fauxware_macho_multiarch")


def test_universal2_is_compatible():
    """Test that the Universal2 backend correctly identifies universal binary files."""
    with open(FATBIN, "rb") as f:
        assert Universal2.is_compatible(f)

    # A regular MachO should not be detected as universal
    macho = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    with open(macho, "rb") as f:
        assert not Universal2.is_compatible(f)


def test_universal2_autodetect():
    """Test that the loader auto-detects and uses the Universal2 backend."""
    ld = cle.Loader(FATBIN, auto_load_libs=False)
    assert type(ld.main_object) is Universal2


def test_universal2_load_all_slices():
    """Test loading all architecture slices from a universal binary."""
    ld = cle.Loader(FATBIN, auto_load_libs=False)

    main = ld.main_object
    assert isinstance(main, Universal2)
    assert main.is_outer is True
    assert main.has_memory is False

    # Should have two child objects (x86_64 + aarch64)
    assert len(main.child_objects) == 2
    assert len(main.slices) == 2

    # All children should be MachO objects parented to the Universal2
    for child in main.child_objects:
        assert isinstance(child, MachO)
        assert child.parent_object is main

    # Check that both expected architectures are present
    arch_names = {child.arch.name for child in main.child_objects}
    assert "AMD64" in arch_names
    assert "AARCH64" in arch_names


def test_universal2_load_single_arch():
    """Test loading only one architecture slice by specifying an archinfo.Arch instance."""
    # Load only the x86_64 slice
    ld = cle.Loader(FATBIN, auto_load_libs=False, main_opts={"arch": archinfo.ArchAMD64()})
    main = ld.main_object
    assert isinstance(main, Universal2)
    assert len(main.child_objects) == 1
    assert main.child_objects[0].arch.name == "AMD64"

    # Load only the aarch64 slice
    ld = cle.Loader(FATBIN, auto_load_libs=False, main_opts={"arch": archinfo.ArchAArch64()})
    main = ld.main_object
    assert isinstance(main, Universal2)
    assert len(main.child_objects) == 1
    assert main.child_objects[0].arch.name == "AARCH64"


def test_universal2_invalid_arch():
    """Test that requesting a non-existent architecture raises an error."""
    with pytest.raises(KeyError, match="not found in universal binary"):
        cle.Loader(FATBIN, auto_load_libs=False, main_opts={"arch": archinfo.ArchMIPS32()})


def test_universal2_arch_type_error():
    """Test that passing a non-Arch value for arch raises TypeError."""
    with pytest.raises(TypeError, match="arch must be an archinfo.Arch instance"):
        cle.Loader(FATBIN, auto_load_libs=False, main_opts={"arch": "aarch64"})


def test_universal2_available_arches():
    """Test that available_arches reports all architectures from the fat header."""
    ld = cle.Loader(FATBIN, auto_load_libs=False)
    main = ld.main_object

    archs = main.available_arches
    assert len(archs) == 2
    assert "AMD64" in archs
    assert "AARCH64" in archs

    # available_arches should reflect the full header even when a single arch is loaded
    ld = cle.Loader(FATBIN, auto_load_libs=False, main_opts={"arch": archinfo.ArchAMD64()})
    main = ld.main_object
    assert len(main.available_arches) == 2
    assert len(main.child_objects) == 1


def test_universal2_child_names():
    """Test that child objects have descriptive names including architecture."""
    ld = cle.Loader(FATBIN, auto_load_libs=False)
    main = ld.main_object

    names = {child.binary_basename for child in main.child_objects}
    assert any("[AMD64]" in n for n in names)
    assert any("[AARCH64]" in n for n in names)
