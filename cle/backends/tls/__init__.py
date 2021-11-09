import logging
from typing import Optional

from ..relocation import Relocation
from ...errors import CLEError
from .. import Backend

_l = logging.getLogger(__name__)


class ThreadManager:
    """
    This class tracks what data is thread-local and can generate thread initialization images

    Most of the heavy lifting will be handled in a subclass
    """
    def __init__(self, loader, arch, max_modules=256):
        self.loader = loader
        self.arch = arch
        self.max_modules = max_modules
        self.modules = []
        self.threads = []

    def register_object(self, obj):
        if not obj.tls_used:
            return False
        if len(self.modules) >= self.max_modules:
            raise CLEError("Too many loaded modules for TLS to handle... file this as a bug")
        obj.tls_module_id = len(self.modules)

        self.modules.append(obj)
        return True

    @staticmethod
    def initialization_image(obj) -> Optional[bytes]:
        if obj.tls_data_start < 0:
            _l.warning("The provided object has a negative tls_data_start. Skip TLS loading.")
            return None
        if obj.tls_data_size <= 0:
            _l.warning("The provided object has an invalid tls_data_size. Skip TLS loading.")
            return None
        return obj.memory.load(obj.tls_data_start, obj.tls_data_size).ljust(obj.tls_block_size, b'\0')

    def new_thread(self, insert=True):
        thread = self._thread_cls(self)
        if insert:
            self.loader._internal_load(thread)
            self.threads.append(thread)
        return thread

    @property
    def _thread_cls(self):
        raise NotImplementedError("This platform doesn't have an implementation of thread-local storage")


class InternalTLSRelocation(Relocation):
    AUTO_HANDLE_NONE = True

    def __init__(self, val, offset, owner):
        super().__init__(owner, None, offset)
        self.val = val

    @property
    def value(self):
        return self.val + self.owner.mapped_base

class TLSObject(Backend):
    def __init__(self, loader, arch):
        super().__init__('cle##tls', None, loader=loader, arch=arch)

from .elf_tls import ELFThreadManager
from .elfcore_tls import ELFCoreThreadManager
from .pe_tls import PEThreadManager
from .minidump_tls import MinidumpThreadManager
