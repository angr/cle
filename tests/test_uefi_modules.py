"""
Tests for the modules cle loads out of a UEFI firmware volume.

A volume holds one FFS file per module, and the file's type says which boot phase the module belongs to, not
whether it is executable. SEC, PEI and DXE phase modules are all loadable images, and the PEI phase ones are
where a real toolchain emits TE rather than PE32.
"""

from __future__ import annotations

import collections
import os
import sys
import unittest

import cle
from cle.backends.uefi_firmware import UefiPE, UefiTE

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
# an EDK2 ArmVirtQemu build: DXE drivers and applications as PE32, the SEC core and the PEI phase as TE
FIRMWARE = os.path.join(TEST_BASE, "tests", "aarch64", "edk2_armvirtqemu.fd")
requires_uefi_firmware = unittest.skipIf(sys.platform == "emscripten", "uefi-firmware is unavailable in Pyodide")


def load():
    return cle.Loader(FIRMWARE, auto_load_libs=False).main_object


def modules_by_name(firmware):
    return {module.user_interface_name: module for module in firmware.child_objects}


@requires_uefi_firmware
def test_every_module_type_loads():
    firmware = load()

    # the volume's DXE drivers are PE32 and its SEC and PEI phase modules are TE; loading only one FFS file type
    # would leave a whole class of module out of the image
    assert collections.Counter(type(module).__name__ for module in firmware.child_objects) == {
        "UefiPE": 96,
        "UefiTE": 10,
    }


@requires_uefi_firmware
def test_pei_phase_modules():
    firmware = load()

    # the SEC core carries no user interface name, so it is the None entry
    assert {name for name, module in modules_by_name(firmware).items() if isinstance(module, UefiTE)} == {
        None,
        "PeiCore",
        "PlatformPei",
        "MemoryInit",
        "CpuPei",
        "DxeIpl",
        "PcdPeim",
        "ResetSystemPei",
        "Tcg2ConfigPei",
        "Tcg2Pei",
    }


@requires_uefi_firmware
def test_dxe_core_and_applications():
    modules = modules_by_name(load())

    # a DXE core file and an application file are PE32 like a driver is, and were dropped along with the TE modules
    for name in ("DxeCore", "UiApp", "BootManagerMenuApp"):
        assert isinstance(modules[name], UefiPE)


@requires_uefi_firmware
def test_real_te_image():
    firmware = load()
    module = modules_by_name(firmware)["MemoryInit"]

    assert module.arch.name == "AARCH64"
    assert [section.name for section in module.sections] == [".text", ".data"]

    text = next(section for section in module.sections if section.name == ".text")
    assert text.contains_addr(module.entry)
    # sub sp, sp, #0xd0; stp x29, x30, [sp, #0x70]
    assert firmware.loader.memory.load(module.entry, 8) == b"\xff\x43\x03\xd1\xfd\x7b\x07\xa9"


@requires_uefi_firmware
def test_relocatable_te_image():
    module = modules_by_name(load())["Tcg2Pei"]

    # a TE image records its relocatability in the base relocation directory, not in the section table
    assert ".reloc" in [section.name for section in module.sections]
    assert module.pic


@requires_uefi_firmware
def test_execute_in_place_modules_keep_their_addresses():
    firmware = load()

    # a module with no base relocations only makes sense at the address it was linked for, so it has to be mapped
    # there rather than packed in wherever the relocatable modules left room
    fixed = [module for module in firmware.child_objects if not module.pic]
    assert fixed
    for module in fixed:
        assert module.mapped_base == module.linked_base


if __name__ == "__main__":
    test_every_module_type_loads()
    test_pei_phase_modules()
    test_dxe_core_and_applications()
    test_real_te_image()
    test_relocatable_te_image()
    test_execute_in_place_modules_keep_their_addresses()
