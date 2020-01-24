#!/usr/bin/env python

import os
import cle
import nose
import logging


def setup():
    """
    Setup the test.
    :return:
            l: the loader
            relocations: a list of all relocations
            ppc_backend: the backend to be used in searches
    """
    test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))
    path = os.path.join(test_location, "ppc", "partial.o")
    l = cle.Loader(path)
    relocations = l.main_object.relocs
    ppc_backend = cle.backends.elf.relocation.ppc

    return l, relocations, ppc_backend


def test_ppc_rel24_relocation(l, relocations, ppc_backend):
    """
    Test R_PPC_REL24 relocations on a PowerPC object file.
    :return:
    """

    # Verify that a faulty branch-and-link instruction operates correctly.
    # Expected bytes: 4b ff ff 05
    byte_value = l.memory.load(0x414838, 4)
    nose.tools.assert_equal(byte_value, b'K\xff\xff\x05')

    # Verify that the symbol in the bl instruction above is correct.
    goodG2B1Source = l.find_symbol("goodG2B1Source")
    nose.tools.assert_equal(goodG2B1Source.relative_addr, 83772)

    # Verify relocated symbol exists in addition to its calculated value.
    found_symbol = False
    for r in relocations:
        if r.symbol.name == "_Znwj" and r.__class__ == ppc_backend.R_PPC_REL24:
            found_symbol = True
            nose.tools.assert_equal(r.value, 1220440101)
            break

    nose.tools.assert_equal(found_symbol, True)


def test_ppc_addr16_ha_relocation(relocations, ppc_backend):
    """
    Test R_PPC_ADDR16_HA relocations on a PowerPC object file.
    :return:
    """

    # Verify relocated symbol exists in addition to its calculated value.
    found_symbol = False
    for r in relocations:
        if r.symbol.name == "CWE123_Write_What_Where_Condition__fgets_22_goodG2B2Global" and r.__class__ == ppc_backend.R_PPC_ADDR16_HA:
            found_symbol = True
            nose.tools.assert_equal(r.value, 67)
            nose.tools.assert_equal(r.relative_addr, 29682)
            break

    nose.tools.assert_equal(found_symbol, True)


def test_ppc_addr16_lo_relocation(relocations, ppc_backend):
    """
    Test R_PPC_ADDR16_LO relocations on a PowerPC object file.
    :return:
    """

    # Verify relocated symbol exists in addition to its calculated value.
    found_symbol = False
    for r in relocations:
        if r.symbol.name == "CWE123_Write_What_Where_Condition__listen_socket_68_badData" and r.__class__ == ppc_backend.R_PPC_ADDR16_LO:
            found_symbol = True
            nose.tools.assert_equal(r.value, 4)
            nose.tools.assert_equal(r.relative_addr, 6930)
            break

    nose.tools.assert_equal(found_symbol, True)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ld, relocs, backend = setup()

    test_ppc_rel24_relocation(ld, relocs, backend)
    test_ppc_addr16_ha_relocation(relocs, backend)
    test_ppc_addr16_lo_relocation(relocs, backend)
