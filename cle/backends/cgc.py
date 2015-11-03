from .elf import ELF
from ..loader import Loader

ELF_HEADER = "7f45 4c46 0101 0100 0000 0000 0000 0000".replace(" ","").decode('hex')
CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ","").decode('hex')

class CGC(ELF):
    def __init__(self, path, *args, **kwargs):
        self.elf_path = Loader._make_tmp_copy(path)
        f = open(self.elf_path, 'r+b')
        f.write(ELF_HEADER)
        f.close()
        super(CGC, self).__init__(self.elf_path, *args, **kwargs)
        self.memory.write_bytes(self.get_min_addr(), CGC_HEADER) # repair CGC header
        self.binary = self.elf_path
        self.os = 'cgc'
        self.execstack = True # the stack is always executable in CGC

    supported_filetypes = ['cgc']
