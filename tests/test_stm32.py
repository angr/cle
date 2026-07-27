from __future__ import annotations

import io
import struct

import cle


def test_stm32_backend_is_discovered_automatically():
    initial_sp = 0x20001000
    reset_handler = 0x08000101
    firmware = bytearray(0x200)
    struct.pack_into("<II", firmware, 0, initial_sp, reset_handler)
    firmware[0x100:0x104] = b"\x00\xbf\x00\xbf"

    loader = cle.Loader(io.BytesIO(firmware), auto_load_libs=False)

    assert isinstance(loader.main_object, cle.STM32Backend)
    assert cle.ALL_BACKENDS["stm32"] is cle.STM32Backend
    assert loader.main_object.initial_sp == initial_sp
    assert loader.main_object.entry == reset_handler & ~1
    assert loader.main_object.arch.name == "ARMCortexM"
    assert loader.memory.load(0x08000100, 4) == firmware[0x100:0x104]
