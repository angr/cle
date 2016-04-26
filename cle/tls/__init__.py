from ..backends import Backend
from ..memory import Clemory

class TLSObj(Backend):
    """
    This class is used when parsing the Thread Local Storage of a binary.
    """
    def __init__(self, modules, filetype='unknown'):
        super(TLSObj, self).__init__('##cle_tls##', filetype=filetype)
        self.modules = modules
        self.arch = self.modules[0].arch
        self.memory = Clemory(self.arch)

    def finalize(self):
        """
        Lay out the TLS initialization images into memory.
        """
        raise NotImplementedError()

from .elf_tls import ELFTLSObj
from .pe_tls import PETLSObj
