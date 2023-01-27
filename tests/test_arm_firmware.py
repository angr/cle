import os
import struct

import pyvex

import cle

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"))


def test_empty_segements():
    """
    Test for bizarre ELves #1: Energy Micro's compiler makes empty segments

    :return:
    """
    path = os.path.join(test_location, "armel", "efm32gg.elf")
    cle.Loader(path, rebase_granularity=0x1000)
    # If we survive this, we're doing OK!


def test_thumb_object():
    """
    Test for an object file I ripped out of an ARM firmware HAL.

    Uses some nasty relocs

    :return:
    """
    path = os.path.join(test_location, "armel", "i2c_api.o")
    loader = cle.Loader(path, rebase_granularity=0x1000)
    for r in loader.main_object.relocs:
        if r.__class__ == cle.backends.elf.relocation.arm.R_ARM_THM_JUMP24:
            if r.symbol.name == "HAL_I2C_ER_IRQHandler":
                irsb = pyvex.lift(
                    struct.pack("<I", r.value),
                    r.rebased_addr + 1,
                    loader.main_object.arch,
                    bytes_offset=1,
                )
                assert irsb.default_exit_target == r.resolvedby.rebased_addr
                break
    else:
        assert False, "Could not find JUMP24 relocation for HAL_I2C_ER_IRQHandler"


if __name__ == "__main__":
    test_thumb_object()
    test_empty_segements()
