from ..backends import Backend
from ..memory import Clemory

class TLSObj(Backend):
    """
    CLE implements thread-local storage by treating the TLS region as another object to be loaded. Because of the
    complex interactions between TLS and all the other objects that can be loaded into memory, each TLS object will
    perform some basic initialization when instanciated, and then once all other objects have been loaded,
    ``finalize()`` is called.
    """
    def __init__(self, modules):
        super(TLSObj, self).__init__('##cle_tls##')
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
