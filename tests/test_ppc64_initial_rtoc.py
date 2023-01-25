#!/usr/bin/env python

import logging
import os

import cle

test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


def test_ppc64el_abiv2():
    # ABIv2: 'TOC pointer register typically points to the beginning of the .got
    # section + 0x8000.' For more details, see:
    #     http://openpowerfoundation.org/wp-content/uploads/resources/leabi/content/dbdoclet.50655241_66700.html
    libc = os.path.join(test_location, "ppc64el", "fauxware_static")
    ld = cle.Loader(libc, auto_load_libs=False)
    assert not ld.main_object.is_ppc64_abiv1
    assert ld.main_object.is_ppc64_abiv2
    assert ld.main_object.ppc64_initial_rtoc == 0x100E7B00

    # ABIv2, PIC
    libc = os.path.join(test_location, "ppc64el", "fauxware")
    ld = cle.Loader(libc, auto_load_libs=False, main_opts={"base_addr": 0})
    assert not ld.main_object.is_ppc64_abiv1
    assert ld.main_object.is_ppc64_abiv2
    assert ld.main_object.ppc64_initial_rtoc == 0x27F00


def test_ppc64el_abiv1():
    # ABIv1: TOC value can be determined by 'function descriptor pointed at by
    # the e_entry field in the ELF header.' For more details, see:
    #     https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.html#PROC-REG
    libc = os.path.join(test_location, "ppc64", "fauxware")
    ld = cle.Loader(libc, auto_load_libs=False)
    assert ld.main_object.is_ppc64_abiv1
    assert not ld.main_object.is_ppc64_abiv2
    assert ld.main_object.ppc64_initial_rtoc == 0x10018E80


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_ppc64el_abiv1()
    test_ppc64el_abiv2()
