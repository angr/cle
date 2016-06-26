from .elf import ELF
from ..patched_stream import PatchedStream

ELF_HEADER = "7f45 4c46 0101 0100 0000 0000 0000 0000".replace(" ","").decode('hex')
CGC_HEADER = "7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ","").decode('hex')


class CGC(ELF):
    """
    Backend to support the CGC elf format used by the Cyber Grand Challenge competition.

    See : https://github.com/CyberGrandChallenge/libcgcef/blob/master/cgc_executable_format.md
    """
    def __init__(self, binary, *args, **kwargs):
        if hasattr(binary, 'seek'):
            filename = None
            stream = PatchedStream(binary, [(0, ELF_HEADER)])
        else:
            filename = binary
            stream = PatchedStream(open(binary, 'rb'), [(0, ELF_HEADER)])

        kwargs['filename'] = filename
        super(CGC, self).__init__(stream, *args, **kwargs)
        self.memory.write_bytes(self.get_min_addr(), CGC_HEADER) # repair CGC header
        self.os = 'cgc'
        self.execstack = True # the stack is always executable in CGC

    def _load_segment(self, seg):
        if seg.header.p_memsz > 0:
            super(CGC, self)._load_segment(seg)

    supported_filetypes = ['cgc']
