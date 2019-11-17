from .. import Backend
from ...memory import Clemory
from ...errors import CLEError

class TLSObject(Backend):
    """
    CLE implements thread-local storage by treating the TLS region as another object to be loaded. Because of the
    complex interactions between TLS and all the other objects that can be loaded into memory, each TLS object will
    perform some basic initialization when instantiated, and then once all other objects have been loaded,
    ``map_object()`` is called to actually put each object's image into memory.
    """
    def __init__(self, loader, max_modules=256):
        super(TLSObject, self).__init__('cle##tls', loader=loader)
        self.arch = self.loader.main_object.arch
        self.memory = Clemory(self.arch)
        self.modules = []
        self.pic = True
        self.next_module_id = 0
        self.tp_offset = 0
        self.max_modules = max_modules
        self._finalized_modules = None

    def register_object(self, obj):
        """
        Assign some thread-local identifiers to the module (object). Do the heavy lifting in a subclass.
        """
        if len(self.modules) >= self.max_modules:
            raise CLEError("Too many loaded modules for TLS to handle... file this as a bug")
        obj.tls_module_id = self.next_module_id
        self.next_module_id += 1

        self.modules.append(obj)

    def finalize_layout(self):
        """
        Will Be called when all objects have been registered and none have been mapped. Do the heavy
        lifting in a subclass.
        """
        if self._finalized_modules == len(self.modules):
            return
        elif self._finalized_modules is not None:
            raise CLEError("Trying to refinalize the TLS layout with more data. Are you trying to do dynamic loading with TLS? Report this as a bug")

        self._finalized_modules = len(self.modules)
    def map_object(self, obj):
        # Grab the init images and map them into memory
        data = obj.memory.load(obj.tls_data_start, obj.tls_data_size).ljust(obj.tls_block_size, b'\0')
        self.memory.add_backer(self.tp_offset + obj.tls_block_offset, data)

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
