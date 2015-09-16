from .absobj import AbsObj
from .errors import CLEError
import logging
import os

l = logging.getLogger("cle.blob")

__all__ = ('Blob',)

class Blob(AbsObj):
    """
        Representation of a binary blob, i.e. an executable in an unknown file
        format.
    """

    def __init__(self, path, custom_arch=None, custom_offset=None, *args, **kwargs):
        """
        Arguments we expect in kwargs:
            @custom_arch: required, an archinfo.Arch for the binary blob
            @custom_offset: skip this many bytes from the beginning of the file
        """


        if custom_arch is None:
            raise CLEError("Must specify custom_arch when loading blob!")

        super(Blob, self).__init__(path, *args,
                custom_arch=custom_arch,
                custom_offset=custom_offset, **kwargs)

        self.custom_offset = custom_offset if custom_offset is not None else 0

        if self._custom_entry_point is None:
            l.warning("No custom entry point was specified for blob, assuming 0")
            self._custom_entry_point = 0

        self._entry = self._custom_entry_point
        self._max_addr = 0
        self.os = 'unknown'

        self._load(self.custom_offset)

    supported_filetypes = ['elf', 'pe', 'mach-o', 'unknown']

    def get_min_addr(self):
        return 0

    def get_max_addr(self):
        return self._max_addr

    def _load(self, offset, size=None):
        """ Load a segment into memory """
        try:
            f = open(self.binary, 'rb')
        except IOError:
            raise IOError("\tFile %s does not exist" % self.binary)

        if size == 0:
            size = os.path.getsize(self.binary)

        f.seek(offset)
        if size is None:
            string = f.read()
        else:
            string = f.read(size)
        self.memory.add_backer(0, string)
        self._max_addr = len(string)

    def function_name(self, addr): #pylint: disable=unused-argument,no-self-use
        '''
        Blobs don't support function names.
        '''
        return None

    def contains_addr(self, addr):
        return addr in self.memory

    def in_which_segment(self, addr): #pylint: disable=unused-argument,no-self-use
        '''
        Blobs don't support segments.
        '''
        return None
