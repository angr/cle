from __future__ import annotations

from .generic import (
    IMAGE_REL_BASED_DIR64,
    IMAGE_REL_BASED_HIGH,
    IMAGE_REL_BASED_HIGHADJ,
    IMAGE_REL_BASED_HIGHLOW,
    IMAGE_REL_BASED_LOW,
)
from .pereloc import PEReloc

arch = "RISCV"


class IMAGE_REL_BASED_HIGHADJ(IMAGE_REL_BASED_HIGHADJ):
    pass


class IMAGE_REL_BASED_DIR64(IMAGE_REL_BASED_DIR64):
    pass


class IMAGE_REL_BASED_HIGHLOW(IMAGE_REL_BASED_HIGHLOW):
    pass


class IMAGE_REL_BASED_HIGH(IMAGE_REL_BASED_HIGH):
    pass


class IMAGE_REL_BASED_LOW(IMAGE_REL_BASED_LOW):
    pass


class IMAGE_REL_BASED_RISCV_HIGH20(PEReloc):
    pass


class IMAGE_REL_BASED_RISCV_LOW12I(PEReloc):
    pass


class IMAGE_REL_BASED_RISCV_LOW12S(PEReloc):
    pass
