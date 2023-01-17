from typing import Optional, Dict
import logging
from functools import singledispatchmethod
from dataclasses import dataclass
import io
import mmap
from uuid import UUID

import archinfo

try:
    import uefi_firmware
except ImportError:
    uefi_firmware = None

from . import Backend, register_backend
from ..errors import CLEError, CLEUnknownFormatError
from .pe import PE

l = logging.getLogger(__name__)


class UefiDriverLoadError(Exception):
    pass


class UefiFirmware(Backend):
    is_default = True

    @classmethod
    def _to_bytes(cls, fileobj: io.IOBase):
        try:
            fileno = fileobj.fileno()
        except io.UnsupportedOperation:
            pass
        else:
            return mmap.mmap(fileno, 0, access=mmap.ACCESS_READ)

        if isinstance(fileobj, io.BytesIO):
            return fileobj.getbuffer()

        # fuck it, we'll do it live
        fileobj.seek(0)
        return fileobj.read()

    @classmethod
    def is_compatible(cls, stream):
        if uefi_firmware is None:
            return False

        buffer = cls._to_bytes(stream)
        parser = uefi_firmware.AutoParser(buffer)
        return parser.type() != "unknown"

    def __init__(self, *args, **kwargs):
        if uefi_firmware is None:
            raise CLEError("run `pip install uefi_firmware==1.10` to load UEFI firmware")
        super().__init__(*args, **kwargs)

        # hack: we are using a loader internal method in a non-kosher way which will cause our children to be
        # marked as the main binary if we are also the main binary
        # work around this by setting ourself here:
        if self.loader.main_object is None:
            self.loader.main_object = self

        self._drivers: Dict[UUID, "UefiModule"] = {}
        self._drivers_pending: Dict[UUID, "UefiModulePending"] = {}

        self.set_arch(archinfo.arch_from_id("x86_64"))  # TODO: ???

        buffer = self._to_bytes(self._binary_stream)
        parser = uefi_firmware.AutoParser(buffer)
        firmware = parser.parse()
        self._load(firmware)

        while self._drivers_pending:
            uuid, pending = self._drivers_pending.popitem()
            try:
                child = pending.build(self, uuid)
            except UefiDriverLoadError as e:
                l.warning("Failed to load %s: %s", uuid, e.args[0])
            else:
                self._drivers[uuid] = child
                child.parent_object = self
                self.child_objects.append(child)

        if self.child_objects:
            self.arch = self.child_objects[0].arch
        else:
            l.warning("Loaded empty static archive?")
        self.has_memory = False
        self.pic = True

        # hack pt. 2
        if self.loader.main_object is self:
            self.loader.main_object = None

    @singledispatchmethod
    def _load(self, uefi_obj):
        raise CLEUnknownFormatError(f"Can't load firmware object: {uefi_obj}")

    @_load.register
    def _load_generic(self, uefi_obj: uefi_firmware.FirmwareObject):
        for obj in uefi_obj.objects:
            self._load(obj)

    @_load.register
    def _load_none(self, uefi_obj: None):
        pass

    @_load.register
    def _load_firmwarefile(self, uefi_obj: uefi_firmware.uefi.FirmwareFile):
        if uefi_obj.type == 7:  # driver
            uuid = UUID(bytes=uefi_obj.guid)
            self._drivers_pending[uuid] = UefiModulePending()
        self._load_generic(uefi_obj)

    @_load.register
    def _load_firmwarefilesection(self, uefi_obj: uefi_firmware.uefi.FirmwareFileSystemSection):
        pending = self._drivers_pending.get(UUID(bytes=uefi_obj.guid), None)
        if pending is not None:
            if uefi_obj.type == 16:  # pe32 image
                pending.pe_image = uefi_obj.content
            elif uefi_obj.type == 21:  # user interface name
                pending.name = uefi_obj.content.decode("utf-16").strip("\0")
        self._load_generic(uefi_obj)


@dataclass
class UefiModulePending:
    name: Optional[str] = None
    pe_image: Optional[bytes] = None
    # version
    # dependencies

    def build(self, parent: UefiFirmware, guid: UUID) -> "UefiModule":
        if self.pe_image is not None:
            return UefiModule(
                None, io.BytesIO(self.pe_image), is_main_bin=False, loader=parent.loader, name=self.name, guid=guid
            )
        else:
            raise UefiDriverLoadError("Missing PE Image section")


class UefiModule(PE):
    def __init__(self, *args, guid: UUID, name: Optional[str], **kwargs):
        super().__init__(*args, **kwargs)
        self.guid = guid
        self.user_interface_name = name

        if self.linked_base == 0:
            self.pic = True

    def __repr__(self):
        return f'<{type(self).__name__} Object {self.guid}{f" {self.user_interface_name}" if self.user_interface_name else ""}, maps [{self.min_addr:#x}:{self.max_addr:#x}]>'


register_backend("uefi", UefiFirmware)
