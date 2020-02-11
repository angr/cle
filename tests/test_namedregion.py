
import os

import nose.tools
from cle import Loader
from cle.backends import NamedRegion

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_basic_named_region():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    l = Loader(bin_path)
    # Standard CortexM regions
    mmio = NamedRegion("mmio", 0x40000000, 0x50000000)
    sys = NamedRegion("sys", 0xe000e000, 0xe0010000)
    l.dynamic_load(mmio)
    l.dynamic_load(sys)

    # In order to ensure static analysis works, we must be able to ask
    # CLE what owns these addresses and get a valid answer.
    obj1 = l.find_object_containing(0x4000023c)
    obj2 = l.find_object_containing(0xe000ed08)
    nose.tools.assert_not_equal(obj1, None)
    nose.tools.assert_not_equal(obj2, None)
    nose.tools.assert_equal(obj1.name, 'mmio')
    nose.tools.assert_equal(obj2.name, 'sys')



if __name__ == "__main__":
    test_basic_named_region()
