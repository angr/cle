# pylint:disable=no-self-use,missing-class-docstring
import os
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestDwarfResiliency(TestCase):
    def test_dwarf_pyelftools_keyerrors(self):
        binary_path = os.path.join(TESTS_BASE, "i386", "dwarf_resiliency_0")
        _ = cle.Loader(binary_path, auto_load_libs=False, load_debug_info=True)


if __name__ == "__main__":
    main()
