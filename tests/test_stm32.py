from __future__ import annotations

import io
import os
import struct

import pytest

import cle
from cle.backends.stm32 import VectorTable

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


def test_stm32_vector_table_reads_peripheral_irq_handlers():
    """
    The ctypes fields cover the 16 system exception vectors only; the peripheral IRQ vectors that
    follow them are parsed out of the rest of the image.
    """
    loader = cle.Loader(FIRMWARE, auto_load_libs=False)
    elf = cle.Loader(FIRMWARE_ELF, auto_load_libs=False)
    main_object = loader.main_object
    assert isinstance(main_object, cle.STM32Backend)
    vector_table = main_object.vector_table

    # This firmware routes every peripheral interrupt to the startup file's shared default handler.
    default_handler_symbol = elf.find_symbol("Default_Handler")
    assert default_handler_symbol is not None
    default_handler = default_handler_symbol.rebased_addr
    for irq_num in range(12):
        handler = vector_table.get_irq_handler(irq_num)
        assert handler == vector_table.irq_handlers[irq_num]
        assert handler & ~1 == default_handler
        assert handler & 1, "a Cortex-M vector carries the Thumb bit"


def test_stm32_vector_table_stops_at_the_nvic_limit():
    """
    The image runs for thousands of words past its vector table, and none of the words beyond the
    NVIC's last interrupt line is a vector.
    """
    with open(FIRMWARE, "rb") as f:
        image = f.read()
    vector_table = VectorTable.from_bytes(image)

    words_after_the_system_vectors = (len(image) - VectorTable._size_()) // 4
    assert words_after_the_system_vectors > VectorTable.MAX_IRQ_VECTORS
    assert len(vector_table.irq_handlers) == VectorTable.MAX_IRQ_VECTORS
    assert vector_table.get_irq_handler(VectorTable.MAX_IRQ_VECTORS) == 0


def test_stm32_vector_table_reports_irq_vectors_the_image_does_not_hold():
    with open(FIRMWARE, "rb") as f:
        system_vectors_only = f.read(64)

    table = VectorTable.from_bytes(system_vectors_only)
    assert table.irq_handlers == ()
    assert table.get_irq_handler(0) == 0


def test_stm32_vector_table_rejects_a_negative_irq_number():
    """
    Without this, IRQ -16 through -1 would silently read the system exception vectors instead.
    """
    with open(FIRMWARE, "rb") as f:
        vector_table = VectorTable.from_bytes(f.read())

    with pytest.raises(ValueError):
        vector_table.get_irq_handler(-1)
