import binascii

from ...address_translator import AT
from .. import register_backend
from ..elf import ELF
from ...patched_stream import PatchedStream

ELF_HEADER = binascii.unhexlify("7f45 4c46 0101 0100 0000 0000 0000 0000".replace(" ", ""))
CGC_HEADER = binascii.unhexlify("7f43 4743 0101 0143 014d 6572 696e 6f00".replace(" ", ""))


class CGC(ELF):
    """
    Backend to support the CGC elf format used by the Cyber Grand Challenge competition.

    See : https://github.com/CyberGrandChallenge/libcgcef/blob/master/cgc_executable_format.md
    """
    is_default = True # Tell CLE to automatically consider using the CGC backend

    def __init__(self, binary, *args, **kwargs):
        if hasattr(binary, 'seek'):
            filename = None
            stream = PatchedStream(binary, [(0, ELF_HEADER)])
        else:
            filename = binary
            stream = PatchedStream(open(binary, 'rb'), [(0, ELF_HEADER)])
        kwargs['filename'] = filename
        super(CGC, self).__init__(stream, *args, **kwargs)
        self.memory.store(AT.from_raw(0, self).to_rva(), CGC_HEADER)  # repair the CGC header
        self.os = 'cgc'
        self.execstack = True  # the stack is always executable in CGC

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith(b'\x7fCGC'):
            return True
        return False

    def _load_segment(self, seg):
        if seg.header.p_memsz > 0:
            super(CGC, self)._load_segment(seg)

    supported_filetypes = ['cgc']

register_backend('cgc', CGC)
