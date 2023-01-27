#!/usr/bin/env python

import os
import struct

import pyvex

import cle


def setup():
    """
    Setup the test.
    :return:
            l: the loader
            relocations: a list of all relocations
            ppc_backend: the backend to be used in searches
    """
    test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"))
    path = os.path.join(test_location, "ppc", "partial.o")
    loader = cle.Loader(path)
    relocations = loader.main_object.relocs
    ppc_backend = cle.backends.elf.relocation.ppc

    return loader, relocations, ppc_backend


def test_ppc_rel24_relocation():
    """
    Test R_PPC_REL24 relocations on a PowerPC object file.
    :return:
    """
    loader, relocations, ppc_backend = setup()

    # Verify that a faulty branch-and-link instruction operates correctly.
    # Expected bytes: 4b ff ff 05
    byte_value = loader.memory.load(0x414838, 4)
    assert byte_value == b"K\xff\xff\x05"

    # Verify that the symbol in the bl instruction above is correct.
    goodG2B1Source = loader.find_symbol("goodG2B1Source")
    assert goodG2B1Source.relative_addr == 83772

    # Verify relocated symbol exists in addition to its calculated value.
    found_symbol = False
    for r in relocations:
        if r.symbol.name == "_Znwj" and r.__class__ == ppc_backend.R_PPC_REL24:
            found_symbol = True
            irsb = pyvex.lift(struct.pack(">I", r.value), r.rebased_addr, r.arch)
            assert irsb.constant_jump_targets == {r.symbol.resolvedby.rebased_addr}
            break

    assert found_symbol


def test_ppc_addr16_ha_relocation():
    """
    Test R_PPC_ADDR16_HA relocations on a PowerPC object file.
    :return:
    """
    _, relocations, ppc_backend = setup()

    # Verify relocated symbol exists in addition to its calculated value.
    found_symbol = False
    for r in relocations:
        if (
            r.symbol.name == "CWE123_Write_What_Where_Condition__fgets_22_goodG2B2Global"
            and r.__class__ == ppc_backend.R_PPC_ADDR16_HA
        ):
            found_symbol = True
            assert r.value == 67
            assert r.relative_addr == 29682
            break

    assert found_symbol


def test_ppc_addr16_lo_relocation():
    """
    Test R_PPC_ADDR16_LO relocations on a PowerPC object file.
    :return:
    """
    _, relocations, ppc_backend = setup()

    # Verify relocated symbol exists in addition to its calculated value.
    found_symbol = False
    for r in relocations:
        if (
            r.symbol.name == "CWE123_Write_What_Where_Condition__listen_socket_68_badData"
            and r.__class__ == ppc_backend.R_PPC_ADDR16_LO
        ):
            found_symbol = True
            assert r.value == 4
            assert r.relative_addr == 6930
            break

    assert found_symbol


if __name__ == "__main__":
    test_ppc_rel24_relocation()
    test_ppc_addr16_ha_relocation()
    test_ppc_addr16_lo_relocation()
