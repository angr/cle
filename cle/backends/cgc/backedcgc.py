from __future__ import annotations

from cle.address_translator import AT
from cle.backends.backend import register_backend
from cle.backends.region import Segment

from .cgc import CGC


class FakeSegment(Segment):
    """
    A segment covering memory that the memory backer supplies but the file does not map, such as the stack and heap of
    a process dump. It is readable and writable by Region's defaults, and never executable.
    """

    def __init__(self, start, size):
        super().__init__(0, start, 0, size)

    @property
    def is_executable(self) -> bool:
        return False


class BackedCGC(CGC):
    """
    This is a backend for CGC executables that allows user provide a memory backer and a register backer as the
    initial state of the running binary.
    """

    is_default = True  # Tell CLE to automatically consider using the BackedCGC backend

    def __init__(
        self,
        *args,
        memory_backer=None,
        register_backer=None,
        writes_backer=None,
        permissions_map=None,
        current_allocation_base=None,
        **kwargs,
    ):
        """
        :param path:                    File path to CGC executable.
        :param memory_backer:           A dict of memory content, with beginning address of each segment as key and
                                        actual memory content as data.
        :param register_backer:         A dict of all register contents. EIP will be used as the entry point of this
                                        executable.
        :param writes_backer:           A list of the sizes of the writes the process made to stdout.
        :param permissions_map:         A dict of memory region to permission flags
        :param current_allocation_base: An integer representing the current address of the top of the CGC heap.
        """
        super().__init__(*args, **kwargs)

        # Both backers are optional mappings. Normalizing them here keeps the rest of the backend, and
        # thread_registers(), from having to special-case a missing one.
        self.memory_backer = memory_backer if memory_backer is not None else {}
        self.register_backer = register_backer if register_backer is not None else {}
        self.writes_backer = writes_backer
        self.permissions_map = permissions_map
        self.current_allocation_base = current_allocation_base

        for seg in self.segments:
            if seg.is_executable:
                exec_seg_addr = seg.vaddr
                break
        else:
            raise ValueError("Couldn't find executable segment?")

        # Segment vaddrs and the backers the caller passes in are linked addresses, but this object's memory is keyed
        # relative to its base, so every address has to be translated before it reaches self.memory.
        exec_seg_rva = AT.from_lva(exec_seg_addr, self).to_rva()

        # The dump replaces everything the file mapped except the code itself. remove_backer() mutates the backer
        # list, so walk a copy of it.
        for start, _ in list(self.memory._backers):
            if start != exec_seg_rva:
                self.memory.remove_backer(start)

        for start, data in sorted(self.memory_backer.items()):
            if self.find_segment_containing(start) is None:
                # A region the process had mapped but the file does not describe, such as the stack or the heap.
                self.segments.append(FakeSegment(start, len(data)))

            if start == exec_seg_addr:
                continue

            relative_start = AT.from_lva(start, self).to_rva()
            if relative_start in self.memory:
                raise ValueError(f"Memory backer at {start:#x} overlaps memory already loaded from the file")

            self.memory.add_backer(relative_start, data)

        if "eip" in self.register_backer:
            self._entry = self.register_backer["eip"]

    @staticmethod
    def is_compatible(stream):
        return False  # Don't use this for anything unless it's manual

    @property
    def threads(self):
        return [0]

    def thread_registers(self, thread=None):
        # Backend.thread_registers is documented to return a mapping, and angr's SimOS iterates it with .items().
        return self.register_backer


register_backend("backedcgc", BackedCGC)
