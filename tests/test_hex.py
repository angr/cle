#!/usr/bin/env python

import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))

def test_macho():
    """
    Basic smoke-test for the Mach-O loader
    :return:
    """
    machofile = os.path.join(TEST_BASE, 'tests', 'armel', 'i2c_master_read-arduino_mzero.hex')
    ld = cle.Loader(machofile, auto_load_libs=False, main_opts={'custom_arch':"ARMEL"})
    nose.tools.assert_true(isinstance(ld.main_bin,cle.Hex))
    nose.tools.assert_equals(ld.main_bin.os, 'unknown')
    nose.tools.assert_equals(ld.main_bin.entry,0x44cd)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_macho()
