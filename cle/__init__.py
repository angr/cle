"""
CLE

..  automodule:: cle.loader
    :members:
..  automodule:: cle.memory
    :members:
..  automodule:: cle.tls
    :members:
..  automodule:: cle.relocations
    :members:
..  automodule:: cle.backends
    :members:
"""

import logging
logging.getLogger("cle").addHandler(logging.NullHandler())

from .loader import *
from .memory import *
from .errors import *
from .backends import *
