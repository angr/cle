#!/usr/bin/env python

import logging
import cle

import os

test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


def test_ppc():
    libc = os.path.join(test_location, "ppc", "libc.so.6")
    ld = cle.Loader(libc, auto_load_libs=True, main_opts={"base_addr": 0})
    # This tests the relocation of _rtld_global_ro in ppc libc6.
    # This relocation is of type 20, and relocates a non-local symbol
    relocated = ld.memory.unpack_word(0x18ACE4)
    assert relocated % 0x1000 == 0xF666E320 % 0x1000


def test_mipsel():
    ping = os.path.join(test_location, "mipsel", "darpa_ping")
    skip = ["libgcc_s.so.1", "libresolv.so.0"]
    ld = cle.Loader(ping, skip_libs=skip)
    dep = set(ld._satisfied_deps)
    loadedlibs = set(ld.shared_objects)

    # 1) check dependencies and loaded binaries
