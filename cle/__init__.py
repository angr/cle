"""
CLE is an extensible binary loader. Its main goal is to take an executable program and any libraries it depends on and
produce an address space where that program is loaded and ready to run.

The primary interface to CLE is the Loader class.
"""

import logging
logging.getLogger("cle").addHandler(logging.NullHandler())

# pylint: disable=wildcard-import
from . import utils
from .loader import *
from .memory import *
from .errors import *
from .backends import *
from .backends.tls import *
from .backends.externs import *
from .patched_stream import *
from .gdb import *
