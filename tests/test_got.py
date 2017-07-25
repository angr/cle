#!/usr/bin/env python

import nose
import logging
import cle

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                             os.path.join('..', '..', 'binaries', 'tests'))

def test_ppc():
    libc = os.path.join(test_location, 'ppc', 'libc.so.6')
    ld = cle.Loader(libc, auto_load_libs=True, main_opts={'custom_base_addr': 0})
    # This tests the relocation of _rtld_global_ro in ppc libc6.
    # This relocation is of type 20, and relocates a non-local symbol
    relocated = ld.memory.read_addr_at(0x18ace4)
    nose.tools.assert_equal(relocated % 0x1000, 0xf666e320 % 0x1000)

def test_mipsel():
    ping = os.path.join(test_location, 'mipsel', 'darpa_ping')
    skip=['libgcc_s.so.1', 'libresolv.so.0']
    ld = cle.Loader(ping, skip_libs=skip)
    dep = set(ld._satisfied_deps)
    loadedlibs = set(ld.shared_objects)

    # 1) check dependencies and loaded binaries
    nose.tools.assert_true(dep.issuperset({'libresolv.so.0', 'libgcc_s.so.1', 'libc.so.6', 'ld.so.1'}))
    nose.tools.assert_true(loadedlibs.issuperset({'libc.so.6', 'ld.so.1'}))

    # 2) Check GOT slot containts the right address
    # Cle: 4494036
    # got = ld.find_symbol_got_entry('__uClibc_main')
    # addr = ld.memory.read_addr_at(got)
    # nose.tools.assert_equal(addr, sproc_addr)
    # TODO: Get the right version of uClibc and devise a test that doesn't use angr

    ioctl = ld.find_relevant_relocations("ioctl").next()
    setsockopt = ld.find_relevant_relocations("setsockopt").next()

    nose.tools.assert_equal(ioctl.rebased_addr, 4494300)
    nose.tools.assert_equal(setsockopt.rebased_addr, 4494112)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_mipsel()
    test_ppc()
