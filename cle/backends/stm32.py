from __future__ import annotations

import io
import struct
from ctypes import LittleEndianStructure, c_uint32
from typing import BinaryIO

import archinfo

from cle.backends.backend import Backend, register_backend
from cle.backends.region import Segment


class VectorTable(LittleEndianStructure):
    """
    Zero-copy parser for Cortex-M vector table using ctypes Structure.
    Standard ARM Cortex-M vector table with system exception vectors.
    """

    _fields_ = [
        ("initial_sp", c_uint32),  # 0x00: Initial stack pointer
        ("reset_handler", c_uint32),  # 0x04: Reset handler
        ("nmi_handler", c_uint32),  # 0x08: NMI handler
        ("hardfault_handler", c_uint32),  # 0x0C: Hard fault handler
        ("memmanage_handler", c_uint32),  # 0x10: Memory management fault
        ("busfault_handler", c_uint32),  # 0x14: Bus fault handler
        ("usagefault_handler", c_uint32),  # 0x18: Usage fault handler
        ("reserved1", c_uint32),  # 0x1C: Reserved
        ("reserved2", c_uint32),  # 0x20: Reserved
        ("reserved3", c_uint32),  # 0x24: Reserved
        ("reserved4", c_uint32),  # 0x28: Reserved
        ("svcall_handler", c_uint32),  # 0x2C: SVCall handler
        ("debugmon_handler", c_uint32),  # 0x30: Debug monitor handler
        ("reserved5", c_uint32),  # 0x34: Reserved
        ("pendsv_handler", c_uint32),  # 0x38: PendSV handler
        ("systick_handler", c_uint32),  # 0x3C: SysTick handler
    ]

    @property
    def reset_handler_addr(self) -> int:
        """Reset handler address with Thumb bit cleared"""
        return self.reset_handler & (~1)

    def get_irq_handler(self, data: bytes, irq_num: int) -> int:
        """Get peripheral interrupt handler address (IRQ 0+)"""
        vector_offset = (16 + irq_num) * 4
        if vector_offset + 4 > len(data):
            return 0
        return struct.unpack_from("<I", data, vector_offset)[0]

    @classmethod
    def from_bytes(cls, data: bytes) -> VectorTable:
        """Create VectorTable from bytes data"""
        if len(data) < cls._size_():
            raise ValueError(f"Data too short for vector table (need at least {cls._size_()} bytes)")
        return cls.from_buffer_copy(data[: cls._size_()])

    @classmethod
    def _size_(cls) -> int:
        return struct.calcsize("16I")  # 16 * 4 bytes = 64 bytes


class STM32Segment(Segment):
    def __init__(self, offset, vaddr, filesize, memsize):
        super().__init__(offset, vaddr, filesize, memsize)
        self.is_exec = False

    @property
    def is_executable(self) -> bool:
        return self.is_exec


class STM32Backend(Backend):
    """
    CLE backend for raw STM32 flash blobs that start with a Cortex-M vector table.

    This backend:
    - Implements check_magic_compatibility / is_compatible to let CLE probe the stream.
    - Reads the full blob into memory, extracts initial SP and reset handler.
    - Passes a concrete entry_point (with Thumb bit masked) into Backend so that loader.entry works.
    - Maps the blob at both 0x0 and 0x08000000 addresses.
    - Registers itself under the name "stm32".
    """

    is_default = True

    RAM_LOW = 0x2000_0000
    RAM_HIGH = 0x2010_0000
    RAM_SIZE = 0x10_0000  # 1MB RAM (covers most STM32 devices)
    DEFAULT_LOAD_ADDR = 0x0800_0000
    ALIAS_LOAD_ADDR = 0x0

    @classmethod
    def check_magic_compatibility(cls, stream: BinaryIO) -> bool:
        # CLE calls this to check quickly if a stream matches the backend.
        # We simply reuse is_compatible semantics (read first 8 bytes, but do not consume the stream).
        pos = stream.tell()
        try:
            head = stream.read(8)
            return cls.is_compatible(head)
        finally:
            stream.seek(pos)

    @classmethod
    def is_compatible(cls, data_or_stream) -> bool:
        """
        Accept either a bytes-like object (when called directly) or a stream (when CLE probes)
        Heuristic:
        - at least 64 bytes for full vector table
        - word0 looks like RAM (0x2000_0000..0x2008_0000)
        - word1 has Thumb bit set (LSB == 1)
        """
        # allow being called with a stream or raw bytes
        if hasattr(data_or_stream, "read"):
            # stream-like
            stream = data_or_stream
            pos = stream.tell()
            try:
                data = stream.read(64)  # Read enough for full vector table
            finally:
                stream.seek(pos)
        else:
            data = data_or_stream

        if not data or len(data) < 64:
            return False

        try:
            vector_table = VectorTable.from_bytes(data)
        except ValueError:
            return False

        # Check if initial SP looks like RAM
        if not (cls.RAM_LOW <= vector_table.initial_sp < cls.RAM_HIGH):
            return False

        # Check if reset handler has Thumb bit set
        if (vector_table.reset_handler & 1) != 1:
            return False

        return True

    def __init__(
        self,
        binary,
        binary_stream: BinaryIO,
        entry_point=None,
        arch: archinfo.Arch | None = None,
        **kwargs,
    ):
        # Read full content from the provided stream (but don't destroy the original; make our own BytesIO)
        orig_pos = binary_stream.tell()
        binary_stream.seek(0)
        data = binary_stream.read()
        size = len(data)
        data_to_map = data[:size]

        binary_stream.seek(orig_pos)

        # parse vector table if present
        vector_table = VectorTable.from_bytes(data)
        entry = vector_table.reset_handler_addr

        # Use a BytesIO so Backend can cache/checksum from a seekable stream
        stream_for_backend = io.BytesIO(data)

        # Pass the parsed entry (absolute) as entry_point so Backend.entry works immediately.
        # If we didn't find an entry, pass None and leave Backend to handle defaults.
        super().__init__(
            binary=binary,
            binary_stream=stream_for_backend,
            entry_point=entry if entry is not None else entry_point,
            arch=archinfo.ArchARMCortexM(),
            force_rebase=False,
            **kwargs,
        )
        self.os = "stm32"

        # store blob data and parsed vector info
        self._data = data
        self.vector_table = vector_table
        self.initial_sp = vector_table.initial_sp
        self.raw_reset = vector_table.reset_handler
        self.entry_from_vector = entry

        # Create segment at 0x0800_0000 (default flash location)
        segment_flash = STM32Segment(
            0,  # offset into file
            self.DEFAULT_LOAD_ADDR,  # vaddr
            size,  # flashsize
            len(self._data),  # memsize
        )
        segment_flash.is_exec = True
        self.segments.append(segment_flash)

        # Create segment at 0x0 (aliased flash location)
        segment_alias = STM32Segment(
            0,  # offset into file
            self.ALIAS_LOAD_ADDR,  # vaddr
            size,  # flashsize
            len(self._data),  # memsize
        )
        segment_alias.is_exec = False
        self.segments.append(segment_alias)

        # Add memory backers with the actual binary data (like Blob backend does)
        self.memory.add_backer(self.DEFAULT_LOAD_ADDR - self.linked_base, data_to_map)
        self.memory.add_backer(self.ALIAS_LOAD_ADDR - self.linked_base, data_to_map)


register_backend("stm32", STM32Backend)
