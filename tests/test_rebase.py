from __future__ import annotations

import os

import archinfo
import pytest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


class MockBackend(cle.backends.Backend):  # pylint: disable=missing-class-docstring
    def __init__(self, size, **kwargs):
        super().__init__("/dev/zero", None, **kwargs)
        self.size = size
        self.pic = True
        self.has_memory = False

    @property
    def max_addr(self):
        return self.mapped_base + self.size - 1


class MockOuterBackend(MockBackend):  # pylint: disable=missing-class-docstring
    is_outer = True


def check_sparse_elf(name):
    """
    Load an i386 image whose two segments are 4 GB apart. Everything the loader places itself must
    be readable through its memory.
    """
    path = os.path.join(TEST_BASE, "tests", "i386", name)
    ld = cle.Loader(path, auto_load_libs=False, main_opts={"backend": "elf"})
    assert (ld.main_object.min_addr, ld.main_object.max_addr) == (0xF800, 0xFFF00FFF)

    extern = ld.extern_object
    tls = ld.tls.new_thread()

    for obj in (extern, tls):
        # the main object starts at 0xf800; anything placed inside its span is unreachable
        assert obj.max_addr < 0xF800
        ld.memory.unpack_word(obj.min_addr)


def test_sparse_main_object():
    # the gap below the main object is 0xf800 bytes, under the default granularity of 0x100000
    check_sparse_elf("sparse_segments")


def test_sparse_main_object_unsorted_program_headers():
    # cle keeps program headers in file order, which does not have to be vaddr order
    check_sparse_elf("sparse_segments_unsorted_phdrs")


def test_rebase_granularity_is_not_a_hard_object_limit():
    """
    Rounding every object up to the rebase granularity caps the loader at one object per granule,
    which a granularity of 0x10000000 reaches after sixteen objects.
    """
    path = os.path.join(TEST_BASE, "tests", "i386", "manysum")
    ld = cle.Loader(path, auto_load_libs=False, rebase_granularity=0x10000000)

    objects = []
    for _ in range(64):
        obj = MockBackend(0x1000, arch=ld.main_object.arch)
        ld.dynamic_load(obj)
        objects.append(obj)

    placed = sorted(objects, key=lambda o: o.min_addr)
    assert placed[-1].max_addr < 2**32
    for lower, upper in zip(placed, placed[1:]):
        assert lower.max_addr < upper.min_addr
    for obj in objects:
        assert ld.find_object_containing(obj.min_addr) is obj


def test_outer_object_mapping_width_is_not_limited_by_child_arch():
    """An outer object maps a collection of children, not one image for the target architecture."""
    pytest.importorskip("pypcode")
    arch = archinfo.ArchPcode("avr8:LE:16:default")

    assert MockBackend(1, arch=arch).mapped_address_bits == 16
    outer = MockOuterBackend(1, arch=arch)
    assert outer.mapped_address_bits == 32

    ld = cle.Loader(outer, auto_load_libs=False, rebase_granularity=0x1000)
    children = [MockBackend(0x1000, arch=arch) for _ in range(32)]
    for child in children:
        ld.dynamic_load(child)

    assert max(child.max_addr for child in children) >= 2**arch.bits
    assert max(child.max_addr for child in children) < 2**outer.mapped_address_bits


def test_real_mode_mapping_width_is_not_limited_by_register_width():
    """Real-mode x86 has a 20-bit linear address space despite using 16-bit registers."""
    pytest.importorskip("pypcode")
    arch = archinfo.ArchPcode("x86:LE:16:Real Mode")

    main = MockBackend(0xFDF7, arch=arch, base_addr=0x100)
    assert main.mapped_address_bits == 20

    ld = cle.Loader(main, auto_load_libs=False, rebase_granularity=0x100)
    child = MockBackend(0x200, arch=arch)
    ld.dynamic_load(child)

    assert (main.min_addr, main.max_addr) == (0x100, 0xFEF6)
    assert (child.min_addr, child.max_addr) == (0xFF00, 0x100FF)


if __name__ == "__main__":
    test_sparse_main_object()
    test_sparse_main_object_unsorted_program_headers()
    test_rebase_granularity_is_not_a_hard_object_limit()
    test_outer_object_mapping_width_is_not_limited_by_child_arch()
    test_real_mode_mapping_width_is_not_limited_by_register_width()
