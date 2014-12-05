from .clexception import CLException
from .abs_obj import AbsObj
import logging
import os

l = logging.getLogger("cle.blob")

class Blob(AbsObj):
    """
        Representation of a binary blob, i.e., an executable in an unknown file
        format.
    """

    def __init__(self, *args, **kwargs):
        """
        Arguments we expect in kwargs:
            @custom_entry_point: where to start the execution in the blob
            @custom_base_addr: at which address shall we load the blob ?
            @custom_offset: skip n bytes from the beginning of the file, where
                n = @custom_offset
        """

        if 'custom_entry_point' not  in kwargs or \
                'custom_base_addr' not in kwargs or \
                'custom_arch' not in kwargs:
            raise CLException("Not enought arguments supplied to load this blob (Blob needs custom_entry_point, custom_base_addr and custom_arch passed as cle_options)")

        if 'custom_offset' not in kwargs:
            l.warning("No custom offset was specified for blob, assuming 0")

        kwargs['blob'] = True
        super(Blob, self).__init__(*args, **kwargs)

        self.custom_offset = kwargs['custom_offset']
        self.custom_base_addr = kwargs['custom_base_addr']
        self.custom_entry_point = kwargs['custom_entry_point']
        self.entry = self.custom_entry_point

        self.load(self.custom_offset)

        self._max_addr = max(self._memory.keys())

    def get_min_addr(self):
        return self.custom_base_addr

    def get_max_addr(self):
        return self._max_addr

    def load(self, offset, size=0):
        """ Load a segment into memory """
        try:
            f = open(self.binary, 'r')
            f.seek(offset)
        except IOError:
            print("\tFile does not exist", self.binary)

        if size == 0:
            size = os.path.getsize(self.binary)

        # Fill the memory dict with addr:value
        for i in range(offset, size):
            self._memory[i + self.custom_base_addr] = f.read(1)

    def function_name(self, addr):
        '''
        Blobs don't support function names.
        '''
        return None

    def contains_addr(self, addr):
        max_addr = self.get_max_addr()
        min_addr = self.get_min_addr()

        return (addr >= min_addr and addr <= max_addr)

    def in_which_segment(self, addr):
        '''
        Blobs don't support segments.
        '''
        return None
