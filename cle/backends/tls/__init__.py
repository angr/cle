from .. import Backend
from ...memory import Clemory

class TLSObject(Backend):
    """
    CLE implements thread-local storage by treating the TLS region as another object to be loaded. Because of the
    complex interactions between TLS and all the other objects that can be loaded into memory, each TLS object will
    perform some basic initialization when instanciated, and then once all other objects have been loaded,
    ``finalize()`` is called.
    """
    def __init__(self, loader):
        super(TLSObject, self).__init__('cle##tls', loader=loader)
        self.arch = self.loader.main_object.arch
        self.memory = Clemory(self.arch)
        self.modules = []
        self.pic = True

    def register_object(self, obj):
        """
        Lay out the TLS initialization images into memory. Do the actual work in a subclass.
        """
        self.modules.append(obj)

    def rebase(self):
        # this isn't the dependency of anything so we need to run our relocations ourselves
        for reloc in self.relocs:
            reloc.relocate()

class InternalTLSRelocation(object):
    def __init__(self, val, offset, owner):
        self.val = val
        self.offset = offset
        self.owner = owner
        self.symbol = None

    def relocate(self):
        self.owner.memory.pack_word(self.offset, self.val + self.owner.mapped_base)

from .elf_tls import ELFTLSObject
from .pe_tls import PETLSObject
