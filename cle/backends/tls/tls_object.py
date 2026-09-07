from __future__ import annotations

import logging

from cle.backends.backend import Backend
from cle.backends.relocation import Relocation
from cle.errors import CLEError

log = logging.getLogger(__name__)


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
    def initialization_image(obj) -> bytes | None:
        if obj.tls_data_start < 0:
            log.warning("The provided object has a negative tls_data_start. Skip TLS loading.")
            return None
        if obj.tls_data_size < 0:
            log.warning("The provided object has an invalid tls_data_size. Skip TLS loading.")
            return None
        if obj.tls_data_size == 0:
            return b"".ljust(obj.tls_block_size, b"\0")
        if obj.tls_data_start + obj.tls_data_size > obj.max_addr - obj.mapped_base + 1:
            # Only the range that is read is bounded, never tls_block_size: an ELF's .tbss legitimately runs
            # past the end of the segment that holds the initial data.
            log.warning(
                "The provided object's TLS data at %#x runs past the end of the object. Skip TLS loading.",
                obj.tls_data_start,
            )
            return None
        try:
            data = obj.memory.load(obj.tls_data_start, obj.tls_data_size)
        except KeyError:
            # The range is inside the object but nothing backs it, because the object's backed memory ends
            # before its virtual extent. Clemory.load raises only when the start itself is unbacked; a range
            # that starts in mapped memory and runs out of it comes back short, and means the same thing.
            # Nothing here is real data, so a block that does not fit in the object is not worth building.
            if obj.tls_data_start + obj.tls_block_size > obj.max_addr - obj.mapped_base + 1:
                log.warning(
                    "The provided object's TLS block at %#x is unmapped and does not fit. Skip TLS loading.",
                    obj.tls_data_start,
                )
                return None
            log.warning("The provided object's TLS data at %#x is not mapped. Zero-filling.", obj.tls_data_start)
            data = b""
        return data.ljust(obj.tls_block_size, b"\0")

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
    __slots__ = ("val",)

    AUTO_HANDLE_NONE = True

    def __init__(self, val, offset, owner):
        super().__init__(owner, None, offset)
        self.val = val

    @property
    def value(self):
        return self.val + self.owner.mapped_base


class TLSObject(Backend):
    def __init__(self, loader, arch):
        super().__init__("cle##tls", None, loader=loader, arch=arch)
