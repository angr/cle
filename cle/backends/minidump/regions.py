from __future__ import annotations

from minidump.streams import MemoryInfoListStream

from cle.backends.region import Section

AP = MemoryInfoListStream.AllocationProtect


class DumpSection(Section):
    """
    Represents a mapped memory section in a dump.
    """

    def __init__(
        self,
        module,
        segment,
        protect,
        vaddr=None,
        size=None,
    ):
        super().__init__(
            module.name,
            (
                segment.start_file_address + (vaddr - segment.start_virtual_address)
                if vaddr
                else segment.start_file_address
            ),
            vaddr or module.baseaddress,
            size or module.size,
        )
        self.protect = protect

    @property
    def is_readable(self) -> bool:
        readable = (
            AP.PAGE_READONLY.value
            | AP.PAGE_READWRITE.value
            | AP.PAGE_WRITECOPY.value
            | AP.PAGE_EXECUTE_READ.value
            | AP.PAGE_EXECUTE_READWRITE.value
            | AP.PAGE_EXECUTE_WRITECOPY.value
        )
        return bool(self.protect.value & readable)

    @property
    def is_writable(self) -> bool:
        writable = AP.PAGE_READWRITE.value | AP.PAGE_EXECUTE_READWRITE.value
        return bool(self.protect.value & writable)

    @property
    def is_executable(self) -> bool:
        executable = (
            AP.PAGE_EXECUTE.value
            | AP.PAGE_EXECUTE_READ.value
            | AP.PAGE_EXECUTE_READWRITE.value
            | AP.PAGE_EXECUTE_WRITECOPY.value
        )
        return bool(self.protect.value & executable)
