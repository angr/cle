#!/usr/bin/env python

import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))

def test_xbe():
    xbe = os.path.join(TEST_BASE, 'tests', 'x86', 'xbox', 'triangle.xbe')
    ld = cle.Loader(xbe, auto_load_libs=False)
    nose.tools.assert_true(isinstance(ld.main_object,cle.XBE))
    nose.tools.assert_equal(ld.main_object.os, 'xbox')
    nose.tools.assert_equal(ld.main_object.mapped_base, 0x10000)
    nose.tools.assert_equal(sorted([sec.name for sec in ld.main_object.sections]),
                             sorted(['.rdata',
                                     '.bss',
                                     '.data',
                                     '.text',
                                     '.tls',
                                     '.idata',
                                     '.reloc',
                                     ]))

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_xbe()
