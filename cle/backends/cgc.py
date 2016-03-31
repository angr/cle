import os

from .elf import ELF
from ..loader import Loader
from ..errors import CLEError

ELF_HEADER = "7f45 4c46 0101 0100 0000 0000 0000 0000".replace(" ","").decode('hex')
CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ","").decode('hex')


class CGC(ELF):
    """
    Backend to support the CGC elf format used by the Cyber Grand Challenge competition.

    See : https://github.com/CyberGrandChallenge/libcgcef/blob/master/cgc_executable_format.md
    """
    def __init__(self, path, *args, **kwargs):
        if hasattr(path, 'seek'):
            raise CLEError("CGC backend can't be used with a file stream")

        self.cgc_path = path
        self.elf_path = self.make_elf_copy(path)
        f = open(self.elf_path, 'r+b')
        f.write(ELF_HEADER)
        f.close()
        super(CGC, self).__init__(self.elf_path, *args, **kwargs)
        self.memory.write_bytes(self.get_min_addr(), CGC_HEADER) # repair CGC header
        self.binary = self.elf_path
        self.os = 'cgc'
        self.execstack = True # the stack is always executable in CGC

    @staticmethod
    def make_elf_copy(cgc_path):
        elf_path = Loader._make_tmp_copy(cgc_path)
        f = open(elf_path, 'r+b')
        f.write(ELF_HEADER)
        f.close()
        return elf_path

    def __setstate__(self, data):
        if not os.path.exists(data['elf_path']):
            data['elf_path'] = self.make_elf_copy(data['cgc_path'])
            data['binary'] = data['elf_path']
        super(CGC, self).__setstate__(data)

    def _load_segment(self, seg):
        if seg.header.p_memsz > 0:
            super(CGC, self)._load_segment(seg)

    supported_filetypes = ['cgc']
