
import os
import cle
from nose.tools import assert_true


test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_thumb_object():
    """
    Test for an object file I ripped out of an ARM firmware HAL.

    Uses some nasty relocs

    :return:
    """
    path = os.path.join(test_location, "armel", "i2c_api.o")
    l = cle.Loader(path, rebase_granularity=0x1000)
    for r in l.main_object.relocs:
        if r.__class__ == cle.backends.elf.relocation.arm.R_ARM_THM_JUMP24:
            if r.symbol.name == 'HAL_I2C_ER_IRQHandler':
                if r.value == 0xbff7f000:
                    break
    else:
        # We missed it
        assert_true(r.value == 0xbff7f000)

if __name__ == "__main__":
    test_thumb_object()
