from collections import OrderedDict

from .elf import ELF
from .pe import PE
from .idabin import IDABin
from .blob import Blob
from .cgc import CGC
from .backedcgc import BackedCGC
from .metaelf import MetaELF

ALL_BACKENDS = OrderedDict((
    ('elf', ELF),
    ('pe', PE),
    ('cgc', CGC),
    ('backedcgc', BackedCGC),
    ('ida', IDABin),
    ('blob', Blob)
))
