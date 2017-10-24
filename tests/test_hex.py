#!/usr/bin/env python

import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))

def test_hex():
    machofile = os.path.join(TEST_BASE, 'tests', 'armel', 'i2c_master_read-arduino_mzero.hex')
    ld = cle.Loader(machofile, auto_load_libs=False, main_opts={'custom_arch':"ARMEL"})
    nose.tools.assert_true(isinstance(ld.main_object,cle.Hex))
    nose.tools.assert_equals(ld.main_object.os, 'unknown')
    nose.tools.assert_equals(ld.main_object.entry,0x44cd)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_hex()
