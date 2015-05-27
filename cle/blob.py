from .absobj import AbsObj
import logging
import os

l = logging.getLogger("cle.blob")

__all__ = ('Blob',)

class Blob(AbsObj):
    """
        Representation of a binary blob, i.e. an executable in an unknown file
        format.
    """

    def __init__(self, path, custom_entry_point, custom_base_addr,
                custom_arch, custom_offset=None, *args, **kwargs):
        """
        Arguments we expect in kwargs:
            @custom_entry_point: where to start the execution in the blob
            @custom_base_addr: at which address shall we load the blob ?
            @custom_offset: skip n bytes from the beginning of the file, where
                n = @custom_offset
        """


        if custom_offset is None:
            l.warning("No custom offset was specified for blob, assuming 0")

        super(Blob, self).__init__(path, *args, blob=True,
                custom_entry_point=custom_entry_point,
                custom_arch=custom_arch,
                custom_base_addr=custom_base_addr,
                custom_offset=custom_offset, **kwargs)

        self.custom_offset = custom_offset if custom_offset is not None else 0
        self.custom_base_addr = custom_base_addr
        self.custom_entry_point = custom_entry_point

        self.entry = self.custom_entry_point
        self._max_addr = self.custom_base_addr

        self.load(self.custom_offset)

    supported_filetypes = ['elf', 'pe', 'mach-o', 'unknown']

    def get_min_addr(self):
        return self.custom_base_addr

    def get_max_addr(self):
        return self._max_addr

    def load(self, offset, size=None):
        """ Load a segment into memory """
        try:
            f = open(self.binary, 'r')
        except IOError:
            raise IOError("\tFile %s does not exist" % self.binary)

        if size == 0:
            size = os.path.getsize(self.binary)

        f.seek(offset)
        if size is None:
            string = f.read()
        else:
            string = f.read(size)
        self.memory.add_backer(self.custom_base_addr, string)
        if self.custom_base_addr + len(string) > self._max_addr:
            self._max_addr = self.custom_base_addr + len(string)

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
