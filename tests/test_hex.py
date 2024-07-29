#!/usr/bin/env python
from __future__ import annotations

import logging
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_hex():
    machofile = os.path.join(TEST_BASE, "tests", "armel", "i2c_master_read-arduino_mzero.hex")
    ld = cle.Loader(machofile, auto_load_libs=False, main_opts={"arch": "ARMEL"})
    assert isinstance(ld.main_object, cle.Hex)
    assert ld.main_object.os == "unknown"
    assert ld.main_object.min_addr == 0
    assert ld.main_object.max_addr == 0x6AF3
    assert ld.main_object.entry == 0x44CD


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_hex()
