#!/usr/bin/env python
from __future__ import annotations

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


def test_ppc64_abiv1_rebased():
    # ABIv1 takes the entry point and the TOC out of the same entry descriptor, and both words are
    # link-time addresses. libc.so.6 is a shared object, so the loader always rebases it.
    lib = os.path.join(test_location, "ppc64", "libc.so.6")
    ld = cle.Loader(lib, auto_load_libs=False, main_opts={"base_addr": 0x10100000})
    main = ld.main_object
    assert isinstance(main, cle.ELF)
    assert main.is_ppc64_abiv1
    assert main.mapped_base == 0x10100000
    assert main.entry == 0x10147B60
    assert main.ppc64_initial_rtoc == 0x102CC6F0
    # the same address, taken from the mapped .got rather than from the descriptor
    assert main.ppc64_initial_rtoc == main.sections_map[".got"].vaddr + 0x8000


def load_relocatable(name):
    ld = cle.Loader(os.path.join(test_location, "ppc64", name), auto_load_libs=False)
    main = ld.main_object
    assert isinstance(main, cle.ELF)
    assert main.is_ppc64_abiv1
    assert main.is_relocatable
    return main


def test_ppc64_abiv1_relocatable_mapping_nothing():
    # e_entry is zero, which is how ELF says there is no entry point, and this object allocates
    # nothing, so following that zero as a descriptor pointer reads memory that is not there.
    main = load_relocatable("empty_object.o")
    assert main.entry == main.mapped_base
    assert main.ppc64_initial_rtoc is None


def test_ppc64_abiv1_relocatable_mapping_code():
    # The same zero e_entry, with .opd and .text at the start of the image, so following it reads
    # the object's own first instructions instead of failing.
    main = load_relocatable("simple_object.o")
    assert main.entry == main.mapped_base
    assert main.ppc64_initial_rtoc is None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_ppc64el_abiv1()
    test_ppc64el_abiv2()
    test_ppc64_abiv1_rebased()
    test_ppc64_abiv1_relocatable_mapping_nothing()
    test_ppc64_abiv1_relocatable_mapping_code()
