from . import Backend, register_backend
from ..errors import CLEError
from .region import Segment
import logging
l = logging.getLogger("cle.named_region")

__all__ = ('NamedRegion',)

class NamedRegion(Backend):
    """
    A NamedRegion represent a region of memory that has a name, a location, but no static content.

    This can be used as a placeholder for memory that should exist in CLE's view, but for which it does not need data,
    like RAM, MMIO, etc
    """
    is_default = False
    has_memory = False
    def __init__(self, name, start, end, **kwargs):
        """
        """
        self.name = name
        self._min_addr = start
        self._max_addr = end

        super(NamedRegion, self).__init__(name, **kwargs)
        self._min_addr = start
        self.linked_base = start
        self._max_addr = end
        self.has_memory = False
        s = Segment(0, start, 0, end - start)
        self.segments.append(s)

    
    def __repr__(self):
         return '<NamedRegion %s, maps [%#x:%#x]>' % (self.name, self.min_addr, self.max_addr)

    @staticmethod
    def is_compatible(stream):
        return stream == 0  # I hate pylint

    @property
    def min_addr(self):
        return self._min_addr

    @property
    def max_addr(self):
        return self._max_addr

    def function_name(self, addr): #pylint: disable=unused-argument,no-self-use
        """
        Blobs don't support function names.
        """
        return None

    def contains_addr(self, addr):
        return self.min_addr <= addr < self.max_addr

    @classmethod
    def check_compatibility(cls, spec, obj): # pylint: disable=unused-argument
        return True


register_backend("named_region", NamedRegion)
