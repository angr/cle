from . import Backend, register_backend
from ..errors import CLEError

import logging
l = logging.getLogger("cle.blob")

__all__ = ('Blob',)

class Blob(Backend):
    """
    Representation of a binary blob, i.e. an executable in an unknown file format.
    """

    def __init__(self, path, custom_offset=None, segments=None, **kwargs):
        """
        :param custom_arch:   (required) an :class:`archinfo.Arch` for the binary blob.
        :param custom_offset: Skip this many bytes from the beginning of the file.
        :param segments:      List of tuples describing how to map data into memory. Tuples
                              are of ``(file_offset, mem_addr, size)``.

        You can't specify both ``custom_offset`` and ``segments``.
        """
        super(Blob, self).__init__(path, **kwargs)

        if self.arch is None:
            raise CLEError("Must specify custom_arch when loading blob!")

        if self._custom_entry_point is None:
            l.warning("No custom_entry_point was specified for blob %s, assuming 0", path)
            self._custom_entry_point = 0

        self._entry = self._custom_entry_point
        self._max_addr = 0
        self._min_addr = 2**64

        try:
            self.linked_base = kwargs['custom_base_addr']
        except KeyError:
            l.warning("No custom_base_addr was specified for blob %s, assuming 0", path)
        self.mapped_base = self.linked_base

        self.os = 'unknown'

        if custom_offset is not None:
            if segments is not None:
                l.error("You can't specify both custom_offset and segments. Taking only the segments data")
            else:
                self.binary_stream.seek(0, 2)
                segments = [(custom_offset, self.linked_base, self.binary_stream.tell() - custom_offset)]
        else:
            if segments is not None:
                pass
            else:
                self.binary_stream.seek(0, 2)
                segments = [(0, self.linked_base, self.binary_stream.tell())]

        for file_offset, mem_addr, size in segments:
            self._load(file_offset, mem_addr, size)

    @staticmethod
    def is_compatible(stream):
        return stream == 0  # I hate pylint

    @property
    def min_addr(self):
        return self._min_addr

    @property
    def max_addr(self):
        return self._max_addr

    def _load(self, file_offset, mem_addr, size):
        """
        Load a segment into memory.
        """

        self.binary_stream.seek(file_offset)
        string = self.binary_stream.read(size)
        self.memory.add_backer(mem_addr - self.linked_base, string)
        self._max_addr = max(len(string) + mem_addr, self._max_addr)
        self._min_addr = min(mem_addr, self._min_addr)

    def function_name(self, addr): #pylint: disable=unused-argument,no-self-use
        """
        Blobs don't support function names.
        """
        return None

    def contains_addr(self, addr):
        return addr in self.memory

    def in_which_segment(self, addr): #pylint: disable=unused-argument,no-self-use
        """
        Blobs don't support segments.
        """
        return None

    @classmethod
    def check_compatibility(cls, spec, obj): # pylint: disable=unused-argument
        return True

register_backend("blob", Blob)
