from __future__ import annotations

import os
import unittest
from unittest import TestCase

import cle

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestTlsResiliency(TestCase):
    @staticmethod
    def test_tls_pe_incorrect_tls_data_start():
        p = os.path.join(test_location, "i386", "windows", "2.exe")
        path_ld = cle.Loader(p)
        assert path_ld is not None
        th = path_ld.tls.new_thread()
        assert th is not None


if __name__ == "__main__":
    unittest.main()
