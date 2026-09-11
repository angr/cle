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
        path_ld = cle.Loader(p, auto_load_libs=True)
        assert path_ld is not None
        th = path_ld.tls.new_thread()
        assert th is not None

    @staticmethod
    def test_tls_pe_zero_fill_larger_than_image():
        # TLS_huge_zero_fill.exe is TLS.exe with IMAGE_TLS_DIRECTORY32.SizeOfZeroFill, the dword at file
        # offset 0x68ec, changed from 0 to 0xf0000000: a 3.75 GiB block out of a 124 KiB image.
        good = cle.Loader(os.path.join(test_location, "x86", "windows", "TLS.exe"), auto_load_libs=False)
        assert good.main_object.tls_data_size == 520
        assert good.main_object.tls_block_size == 520

        bad = cle.Loader(os.path.join(test_location, "x86", "windows", "TLS_huge_zero_fill.exe"), auto_load_libs=False)
        assert bad.main_object.tls_data_size == good.main_object.tls_data_size
        assert bad.main_object.tls_block_size == bad.main_object.tls_data_size

        good_thread = good.tls.new_thread()
        bad_thread = bad.tls.new_thread()
        assert bad_thread.max_addr - bad_thread.mapped_base == good_thread.max_addr - good_thread.mapped_base


if __name__ == "__main__":
    unittest.main()
