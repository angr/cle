from __future__ import annotations

import logging
import struct

import archinfo

from cle.errors import CLEError

from .backend import Backend, register_backend
from .region import Segment

log = logging.getLogger(name=__name__)

__all__ = ("N64",)


# z64 (big-endian) magic. Stored in the first 4 bytes of the ROM: 80 37 12 40.
Z64_MAGIC = b"\x80\x37\x12\x40"

# IPL3 (game-specific boot code) is copied by IPL2 from cart ROM offset 0x40 into
# the RSP DMEM at this virtual address, where it executes from.
BOOTCODE_VADDR = 0xA4000040
BOOTCODE_FILE_OFFSET = 0x40
BOOTCODE_SIZE = 0x1000 - 0x40  # 0xFC0 bytes

# Game code starts at ROM file offset 0x1000.
GAMECODE_FILE_OFFSET = 0x1000

HEADER_SIZE = 0x40


class N64(Backend):
    """
    Loader for Nintendo 64 .z64 ROM images (big-endian).

    The ROM has a 0x40-byte header followed by 0xFC0 bytes of IPL3 boot code
    (file offsets 0x40..0x1000). The remainder of the file is the game program,
    which IPL3 DMAs into RAM starting at the entry PC found at header offset
    0x08. This loader maps the game code at that entry PC. If ``skip_bootcode``
    is False (the default), the IPL3 boot code is also mapped at its
    execution address 0xA4000040 (RSP DMEM).
    """

    is_default = True

    def __init__(self, *args, skip_bootcode: bool = False, **kwargs):
        """
        :param skip_bootcode: If True, do not map the IPL3 boot code segment.
        """
        super().__init__(*args, **kwargs)
        self.set_load_args(skip_bootcode=skip_bootcode)
        self.set_arch(archinfo.arch_from_id("mips32"))
        self.os = "n64"

        self._binary_stream.seek(0, 2)
        file_size = self._binary_stream.tell()
        if file_size < HEADER_SIZE:
            raise CLEError(f"z64 ROM is too small: {file_size} bytes")

        self._binary_stream.seek(0)
        header = self._binary_stream.read(HEADER_SIZE)
        if not header.startswith(Z64_MAGIC):
            raise CLEError("Not a z64 ROM (missing 80 37 12 40 magic)")

        # All header fields are big-endian.
        (
            self.pi_register,
            self.clock_rate,
            self.entry_pc,
            self.release,
            self.crc1,
            self.crc2,
        ) = struct.unpack(">IIIIII", header[0x00:0x18])
        self.image_name = header[0x20:0x34].decode("ascii", errors="replace").rstrip("\x00 ")
        self.cartridge_id = header[0x3C:0x3E]
        self.country_code = header[0x3E:0x3F]
        self.version = header[0x3F]

        self._entry = self.entry_pc

        # Read the game code: everything from file offset 0x1000 to EOF.
        if file_size <= GAMECODE_FILE_OFFSET:
            raise CLEError(f"z64 ROM has no game code (size {file_size} <= 0x1000)")
        self._binary_stream.seek(GAMECODE_FILE_OFFSET)
        game_bytes = self._binary_stream.read(file_size - GAMECODE_FILE_OFFSET)
        game_size = len(game_bytes)

        # mapped/linked base = entry PC so add_backer offsets are non-negative.
        self.mapped_base = self.linked_base = self.entry_pc

        # Game code segment at entry_pc.
        self.memory.add_backer(0, game_bytes)
        self.segments.append(Segment(GAMECODE_FILE_OFFSET, self.entry_pc, game_size, game_size))

        self._min_addr = self.entry_pc
        self._max_addr = self.entry_pc + game_size - 1

        # Boot code segment at 0xA4000040 (RSP DMEM).
        if not skip_bootcode:
            bootcode_bytes = header[BOOTCODE_FILE_OFFSET:] + self._read_bootcode_tail(file_size)
            bootcode_size = len(bootcode_bytes)
            if bootcode_size > 0:
                self.memory.add_backer(BOOTCODE_VADDR - self.linked_base, bootcode_bytes)
                self.segments.append(Segment(BOOTCODE_FILE_OFFSET, BOOTCODE_VADDR, bootcode_size, bootcode_size))
                self._max_addr = max(self._max_addr, BOOTCODE_VADDR + bootcode_size - 1)

    def _read_bootcode_tail(self, file_size: int) -> bytes:
        """Read the portion of IPL3 past the first 0x40 bytes of the header."""
        end = min(GAMECODE_FILE_OFFSET, file_size)
        if end <= HEADER_SIZE:
            return b""
        self._binary_stream.seek(HEADER_SIZE)
        return self._binary_stream.read(end - HEADER_SIZE)

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        magic = stream.read(4)
        stream.seek(0)
        return magic == Z64_MAGIC

    @property
    def min_addr(self):
        return self._min_addr

    @property
    def max_addr(self):
        return self._max_addr

    @classmethod
    def check_compatibility(cls, spec, obj):  # pylint: disable=unused-argument
        return True


register_backend("n64", N64)
