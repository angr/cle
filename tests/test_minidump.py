#!/usr/bin/env python

import archinfo
import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
    os.path.join('..', '..', 'binaries'))

def test_minidump():
    exe = os.path.join(TEST_BASE, 'tests', 'x86', 'windows', 'jusched_x86.dmp')
    ld = cle.Loader(exe, auto_load_libs=False)
    nose.tools.assert_is_instance(ld.main_object, cle.Minidump)
    nose.tools.assert_is_instance(ld.main_object.arch, archinfo.ArchX86)
    nose.tools.assert_equal(ld.main_object.os, 'windows')
    nose.tools.assert_equal(len(ld.main_object.sections), 30)

    sections_map = ld.main_object.sections_map
    nose.tools.assert_in('jusched.exe', sections_map)
    nose.tools.assert_in('kernel32.dll', sections_map)

    nose.tools.assert_equal(len(ld.main_object.threads), 2)
    registers = ld.main_object.thread_registers(0x0548)
    nose.tools.assert_is_instance(registers, dict)
    nose.tools.assert_equal(registers, {
        #'gs': 43,
        #'fs': 83,
        # currently we return the fs segment base value instead of the register itself
        'fs': 2121117696,
        'edi': 2001343136,
        'esi': 2001343136,
        'ebx': 0,
        'edx': 2001343136,
        'ecx': 2001343136,
        'eax': 2121117696,
        'ebp': 33357196,
        'eip': 2000776736,
        'eflags': 580,
        'esp': 33357152
    })

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_minidump()
