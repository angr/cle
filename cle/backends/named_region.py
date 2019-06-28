from . import Backend, register_backend
from ..errors import CLEError
from ..patched_stream import PatchedStream
from .region import Segment
import logging
l = logging.getLogger("cle.blob")

__all__ = ('Blob',)

class NamedRegion(Backend):
    """
    A NamedRegion represent a region of memory that has a name, a location, but no static content.

    This can be used as a placeholder for memory that should exist in CLE's view, but for which it does not need data,
    like RAM, MMIO, etc
    """
    is_default = False

    def __init__(self, name, start, end, **kwargs):
        """
        """

        self._max_addr = start
        self._min_addr = end

        s = Segment(0, start, 0, end - start)
        self.segments.append(s)

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

    def in_which_segment(self, addr): #pylint: disable=unused-argument,no-self-use
        """
        Blobs don't support segments.
        """
        return None

    @classmethod
    def check_compatibility(cls, spec, obj): # pylint: disable=unused-argument
        return True


register_backend("blob", Blob)
