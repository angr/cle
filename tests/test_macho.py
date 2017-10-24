#!/usr/bin/env python

import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))

def test_macho():
    machofile = os.path.join(TEST_BASE, 'tests', 'x86_64', 'fauxware.macho')
    ld = cle.Loader(machofile, auto_load_libs=False)
    nose.tools.assert_true(isinstance(ld.main_object,cle.MachO))
    nose.tools.assert_equals(ld.main_object.os, 'macos')
    nose.tools.assert_equals(ld.main_object.entry,4294970848L)
    nose.tools.assert_equals(sorted(list(ld.main_object.exports_by_name))[-1],'_sneaky')


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_macho()
