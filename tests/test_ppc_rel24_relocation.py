import os
import cle
from nose.tools import assert_equal

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_ppc_rel24_relocation():
    """
    Test PPC REL24 relocations on a PowerPC object file.
    :return:
    """
    path = os.path.join(test_location, "ppc", "partial.o")
    l = cle.Loader(path)

    # Verify that a faulty branch-and-link instruction operates correctly.
    byte_value = l.memory.load(0x414838, 4)
    byte_value = hex(byte_value)
    assert_equal(byte_value, hex(1275068165))

    # Verify that the symbol in the bl instruction above is correct.
    goodG2B1Source = l.find_symbol("goodG2B1Source")
    assert_equal(goodG2B1Source.relative_addr, 83722)

    relocations = l.main_object.relocs
    found_symbol = False
    for r in relocations:
        if r.symbol.name == "_Znwj" and r.__class__ == cle.backends.elf.relocation.ppc.R_PPC_REL24:
            found_symbol = True
            assert_equal(r.value, 1220440101)
            break

    assert_equal(found_symbol, True)

if __name__ == "__main__":
    test_ppc_rel24_relocation()
