from __future__ import annotations

from pathlib import Path

import pytest

import cle
from cle.errors import CLECompatibilityError

BINARIES = Path(__file__).resolve().parents[2] / "binaries" / "tests"
FIRMWARE = BINARIES / "armel" / "i2c_master_read-nucleol152re.bin"
# A C source file whose first eight bytes satisfy the initial-stack-pointer and Thumb-bit checks.
NOT_FIRMWARE = BINARIES / "stm32" / "not_stm32_firmware.c"


def test_stm32_compatibility_requires_a_reset_vector_inside_the_image():
    with FIRMWARE.open("rb") as stream:
        assert cle.STM32Backend.is_compatible(stream)
        assert stream.tell() == 0

    with NOT_FIRMWARE.open("rb") as stream:
        assert not cle.STM32Backend.is_compatible(stream)
        assert stream.tell() == 0


def test_stm32_false_positive_does_not_select_the_backend():
    with pytest.raises(CLECompatibilityError, match="Unable to find a loader backend"):
        cle.Loader(NOT_FIRMWARE, auto_load_libs=False)
