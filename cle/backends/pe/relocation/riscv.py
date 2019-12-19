import logging
from . import generic
from .pereloc import PEReloc

l = logging.getLogger(name=__name__)

arch = 'RISCV'

class IMAGE_REL_BASED_HIGHADJ(generic.IMAGE_REL_BASED_HIGHADJ):
    pass

class IMAGE_REL_BASED_DIR64(generic.IMAGE_REL_BASED_DIR64):
    pass

class IMAGE_REL_BASED_HIGHLOW(generic.IMAGE_REL_BASED_HIGHLOW):
    pass

class IMAGE_REL_BASED_HIGH(generic.IMAGE_REL_BASED_HIGH):
    pass

class IMAGE_REL_BASED_LOW(generic.IMAGE_REL_BASED_LOW):
    pass

class IMAGE_REL_BASED_RISCV_HIGH20(PEReloc):
    pass

class IMAGE_REL_BASED_RISCV_LOW12I(PEReloc):
    pass

class IMAGE_REL_BASED_RISCV_LOW12S(PEReloc):
    pass
