import os

from cle import Loader
from cle.backends import NamedRegion

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_basic_named_region():
    bin_path = os.path.join(test_location, "armel", "lwip_udpecho_bm.elf")
    loader = Loader(bin_path)
    # Standard CortexM regions
    mmio = NamedRegion("mmio", 0x40000000, 0x50000000)
    sys = NamedRegion("sys", 0xE000E000, 0xE0010000)
    loader.dynamic_load(mmio)
    loader.dynamic_load(sys)

    # In order to ensure static analysis works, we must be able to ask
    # CLE what owns these addresses and get a valid answer.
    obj1 = loader.find_object_containing(0x4000023C)
    obj2 = loader.find_object_containing(0xE000ED08)
    assert obj1 is not None
    assert obj2 is not None
    assert obj1.name == "mmio"
    assert obj2.name == "sys"


if __name__ == "__main__":
    test_basic_named_region()
