from .elf import ELF
from .loader import Loader

ELF_HEADER = "7f45 4c46 0101 0100 0000 0000 0000 0000".replace(" ","").decode('hex')

class CGC(ELF):
    def __init__(self, path, *args, **kwargs):
        self.elf_path = Loader._make_tmp_copy(path)
        f = open(self.elf_path, 'r+b')
        f.write(ELF_HEADER)
        f.close()
        super(CGC, self).__init__(self.elf_path, *args, **kwargs)
        self.binary = self.elf_path
        self.os = 'cgc'

    supported_filetypes = ['cgc']
