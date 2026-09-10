"""
Tests for the DOS MZ backend.

tests_src/dos/dos_mz.asm builds hello.exe with Open Watcom: a data segment, two code segments and a
stack, an entry point that is not at the start of the load module, and five relocations -- two far
pointers held in data, the segment word of a far call, and two segment values loaded into a
register.

tests_src/dos/dos_mz_tiny.asm builds hello_tiny.exe with fasm in the .COM memory model, so its
header CS and SS are the sixteen paragraphs below the load module where the Program Segment
Prefix sits:
e_cs and e_ss are both 0xfff0, which only means -16 paragraphs once the wrap is undone. Its SP is
0x0100, which puts the unwrapped reading of SS:SP exactly on the 1 MiB ceiling, so an inclusive
upper bound would accept both readings and have nothing to choose between them.
"""

from __future__ import annotations

import os
import struct

import pytest

try:
    import pypcode
except ImportError:
    pypcode = None

import cle
from cle.backends.mz import MZ, MZRelocation

# the backend takes its architecture from the p-code real-mode language, so without pypcode
# there is no MZ object to assert anything about
pytestmark = pytest.mark.skipif(pypcode is None, reason="pypcode not installed")

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
HELLO = os.path.join(TEST_BASE, "tests", "i386", "dos", "hello.exe")
HELLO_COM = os.path.join(TEST_BASE, "tests", "i386", "dos", "hello.com")
HELLO_TINY = os.path.join(TEST_BASE, "tests", "i386", "dos", "hello_tiny.exe")

# what the linker wrote into the header, read back out of the file
RELOCATION_COUNT = 5
HEADER_SIZE = 0x40
IMAGE_SIZE = 730
INITIAL_CS, INITIAL_IP = 0x0028, 0x0032
INITIAL_SS, INITIAL_SP = 0x0008, 0x0200
ENTRY_RVA = INITIAL_CS * 16 + INITIAL_IP


def load(path=HELLO, **main_opts) -> MZ:
    obj = cle.Loader(path, auto_load_libs=False, main_opts=main_opts).main_object
    assert isinstance(obj, MZ)
    return obj


def file_bytes():
    with open(HELLO, "rb") as f:
        return f.read()


def test_backend_is_selected_without_being_named():
    obj = load()
    assert isinstance(obj, MZ)
    assert obj.os == "dos"
    # real mode has 16-bit registers and a 20-bit linear address space; the loader needs the second one
    assert obj.arch.name == "x86:LE:16:Real Mode"
    assert obj.arch.bits == 16
    assert obj.mapped_address_bits == 20


def test_header_matches_the_file():
    obj = load()
    header = obj.mz_header
    assert header.header_size == HEADER_SIZE
    assert header.image_size == IMAGE_SIZE
    assert (header.initial_cs, header.initial_ip) == (INITIAL_CS, INITIAL_IP)
    assert (header.initial_ss, header.initial_sp) == (INITIAL_SS, INITIAL_SP)
    assert header.relocation_count == RELOCATION_COUNT
    assert len(obj.relocs) == RELOCATION_COUNT


def test_entry_point_is_the_header_cs_ip():
    obj = load()
    assert obj.entry == obj.mapped_base + ENTRY_RVA
    raw = file_bytes()
    assert obj.loader.memory.load(obj.entry, 16) == raw[HEADER_SIZE + ENTRY_RVA : HEADER_SIZE + ENTRY_RVA + 16]


def test_relocations_add_the_load_segment():
    raw = file_bytes()
    obj = load(base_addr=0x10000, force_rebase=True)
    assert obj.mapped_base == 0x10000
    assert obj.load_segment == 0x1000

    relocs = [r for r in obj.relocs if isinstance(r, MZRelocation)]
    assert len(relocs) == RELOCATION_COUNT
    sites = [r.segment * 16 + r.offset for r in relocs]
    assert len(set(sites)) == RELOCATION_COUNT
    for site in sites:
        (unrelocated,) = struct.unpack_from("<H", raw, HEADER_SIZE + site)
        assert (
            obj.loader.memory.unpack_word(obj.mapped_base + site, size=2) == (unrelocated + obj.load_segment) & 0xFFFF
        )


def test_a_zero_load_segment_leaves_the_image_alone():
    # DOS may load at any paragraph, including zero, and the fixups are a no-op there
    obj = load()
    assert obj.load_segment == 0
    raw = file_bytes()
    assert obj.loader.memory.load(obj.mapped_base, IMAGE_SIZE) == raw[HEADER_SIZE : HEADER_SIZE + IMAGE_SIZE]


def test_a_pe_still_loads_as_a_pe():
    # every MZ file the repository tracks is a PE with a DOS stub, and the new backend is probed first
    path = os.path.join(TEST_BASE, "tests", "i386", "test_arrays.exe")
    obj = cle.Loader(path, auto_load_libs=False).main_object
    assert isinstance(obj, cle.backends.PE)


def test_a_com_file_is_not_claimed():
    # a .COM image is a bare load module with no header at all, so there is nothing to parse
    with open(HELLO_COM, "rb") as f:
        assert MZ.is_compatible(f) is False


# hello_tiny.exe, read out of the file: e_cs 0xfff0, e_ip 0x0100, e_ss 0xfff0, e_sp 0x0100,
# e_cparhdr 2, e_minalloc 0x0fe8, no relocations. CS and SS both name the PSP, sixteen paragraphs
# below the load module, so the entry and the stack top are both offset 0 of the image.
TINY_HEADER_SIZE = 0x20
TINY_IMAGE_SIZE = 128


def test_a_wrapped_header_cs_resolves_to_the_start_of_the_load_module():
    obj = load(HELLO_TINY)
    assert (obj.initial_cs, obj.initial_ip) == (0xFFF0, 0x0100)
    # read as an unsigned paragraph count this would be 0xfff00 + 0x100, a megabyte past the image
    assert obj.entry == obj.mapped_base
    with open(HELLO_TINY, "rb") as f:
        image = f.read()[TINY_HEADER_SIZE : TINY_HEADER_SIZE + TINY_IMAGE_SIZE]
    assert obj.loader.memory.load(obj.entry, TINY_IMAGE_SIZE) == image


def test_a_wrapped_header_ss_on_the_real_mode_ceiling_resolves_into_the_allocation():
    obj = load(HELLO_TINY)
    assert (obj.initial_ss, obj.initial_sp) == (0xFFF0, 0x0100)
    # unwrapped this is 0xfff00 + 0x100, which is exactly 1 MiB: the top of real mode, not in it
    assert obj.initial_stack == obj.mapped_base


def test_a_wrapped_segment_still_names_the_psp_after_a_rebase():
    obj = load(HELLO_TINY, base_addr=0x10000, force_rebase=True)
    assert obj.load_segment == 0x1000
    # DOS adds the load segment in 16-bit arithmetic, so both land on the PSP, sixteen paragraphs down
    assert obj.initial_cs_value == 0x0FF0
    assert obj.initial_ss_value == 0x0FF0
