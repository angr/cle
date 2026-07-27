from __future__ import annotations

import io
import os
import struct

import pytest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
# The same Nucleo-L152RE firmware as a raw flash image and as an ELF.
FIRMWARE = os.path.join(TEST_BASE, "tests", "armel", "i2c_master_read-nucleol152re.bin")
FIRMWARE_ELF = os.path.join(TEST_BASE, "tests", "armel", "i2c_master_read-nucleol152re.elf")

INITIAL_SP = 0x2001_4000
RESET_HANDLER = 0x0800_1695


def firmware_with_vectors(initial_sp: int = INITIAL_SP, reset_handler: int = RESET_HANDLER) -> bytes:
    """
    The real flash image with its first two vectors replaced.
    """
    with open(FIRMWARE, "rb") as f:
        image = bytearray(f.read())
    struct.pack_into("<II", image, 0, initial_sp, reset_handler)
    return bytes(image)


def test_stm32_is_autodetected():
    loader = cle.Loader(FIRMWARE, auto_load_libs=False)

    assert cle.ALL_BACKENDS["stm32"] is cle.STM32Backend
    assert type(loader.main_object) is cle.STM32Backend
    assert loader.main_object.arch.name == "ARMCortexM"
    assert loader.main_object.initial_sp == INITIAL_SP


def test_stm32_entry_agrees_with_the_elf_build_of_the_same_firmware():
    """
    Cortex-M runs Thumb code only and angr picks the Thumb lifter from the low bit of the address,
    so the reset vector has to reach the loader with its Thumb bit intact.
    """
    loader = cle.Loader(FIRMWARE, auto_load_libs=False)
    elf = cle.Loader(FIRMWARE_ELF, auto_load_libs=False)

    assert loader.main_object.entry == elf.main_object.entry == RESET_HANDLER
    assert loader.memory.load(RESET_HANDLER & ~1, 16) == elf.memory.load(RESET_HANDLER & ~1, 16)


def test_stm32_maps_flash_at_its_boot_alias():
    loader = cle.Loader(FIRMWARE, auto_load_libs=False)

    assert loader.memory.load(0, 64) == loader.memory.load(cle.STM32Backend.DEFAULT_LOAD_ADDR, 64)


def test_stm32_is_compatible_from_a_nonzero_stream_position():
    """
    Loader._static_backend probes every backend with one shared stream and does not rewind it in
    between, so a backend that read from the stream's current position would inspect the tail of an
    earlier backend's read instead of the vector table.
    """
    with open(FIRMWARE, "rb") as stream:
        stream.seek(8)
        assert cle.STM32Backend.is_compatible(stream)


def test_stm32_rejects_images_without_a_vector_table():
    """
    The backend is probed for every unrecognized blob, so its heuristic has to stay narrow.
    """
    stack_pointer_in_flash = firmware_with_vectors(initial_sp=0x0800_1000)
    reset_handler_without_thumb_bit = firmware_with_vectors(reset_handler=RESET_HANDLER & ~1)
    too_short = firmware_with_vectors()[:0x20]

    for image in (stack_pointer_in_flash, reset_handler_without_thumb_bit, too_short):
        assert not cle.STM32Backend.is_compatible(io.BytesIO(image))
        with pytest.raises(cle.CLECompatibilityError):
            cle.Loader(io.BytesIO(image), auto_load_libs=False)


def test_stm32_entry_point_option_wins_over_the_reset_vector():
    loader = cle.Loader(FIRMWARE, main_opts={"backend": "stm32", "entry_point": 0x0800_2001}, auto_load_libs=False)

    assert loader.main_object.entry == 0x0800_2001


def test_stm32_requested_by_name_rejects_a_truncated_image():
    with pytest.raises(cle.CLECompatibilityError):
        cle.Loader(io.BytesIO(firmware_with_vectors()[:0x20]), main_opts={"backend": "stm32"}, auto_load_libs=False)
