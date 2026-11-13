# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestDwarfResiliency(TestCase):
    def test_dwarf_pyelftools_keyerrors(self):
        binary_path = os.path.join(TESTS_BASE, "i386", "dwarf_resiliency_0")
        _ = cle.Loader(binary_path, auto_load_libs=False, load_debug_info=True)

    def test_fde_without_encoding_augmentation(self):
        """A CIE may omit the "R" augmentation, and then its FDEs have no explicit encoding.

        pyelftools reads that encoding unconditionally and raises KeyError, which used to escape
        the FDE reader and fail the whole load whenever debug information was requested.
        """
        for arch in ("mips", "mipsel"):
            binary_path = os.path.join(TESTS_BASE, arch, "busybox")
            loader = cle.Loader(binary_path, auto_load_libs=False, load_debug_info=True)
            assert loader.main_object is not None


if __name__ == "__main__":
    main()
