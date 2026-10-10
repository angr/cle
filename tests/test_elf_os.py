# pylint:disable=no-self-use
from __future__ import annotations

import os
import unittest

import cle

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))

# cle's CI checks out angr/binaries at master, so this fixture is absent until its pull
# request merges.
brandelf_freebsd = os.path.join(test_location, "aarch64", "brandelf-freebsd-aarch64")


class TestELFOS(unittest.TestCase):
    """
    Tests for the operating system an ELF declares.
    """

    @unittest.skipUnless(os.path.exists(brandelf_freebsd), "needs the branded fixture from angr/binaries")
    def test_legacy_brand_is_honoured(self):
        # brandelf(1) writes the OS name into the identification bytes from byte 8 on and
        # leaves EI_OSABI at ELFOSABI_SYSV. Reading EI_OSABI alone makes this executable a
        # System V one, which sends it to the wrong kernel's syscall table.
        ld = cle.Loader(brandelf_freebsd, auto_load_libs=False)
        assert ld.main_object.os == "UNIX - FreeBSD"

    def test_osabi_is_honoured(self):
        # The same executable before it was branded: here the header names the OS itself.
        ld = cle.Loader(os.path.join(test_location, "dogbolt", "megatest-arm64-freebsd"), auto_load_libs=False)
        assert ld.main_object.os == "UNIX - FreeBSD"

    def test_an_unbranded_sysv_elf_stays_system_v(self):
        # Nothing in the identification bytes of an ordinary ELF spells a brand, and
        # EI_OSABI says ELFOSABI_SYSV for most Linux toolchains, so the OS stays as it was.
        ld = cle.Loader(os.path.join(test_location, "i386", "fauxware"), auto_load_libs=False)
        assert ld.main_object.os == "UNIX - System V"
