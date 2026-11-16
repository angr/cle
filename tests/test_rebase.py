from __future__ import annotations

import io
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


def load_narrow_blob(size):
    """
    Load a blob of ``size`` bytes as a z80 image. The whole 16-bit address space is smaller than a
    single default granule, so every placement in it has to ignore the granularity.
    """
    pytest.importorskip("pypcode")
    arch = archinfo.ArchPcode("z80:LE:16:default")
    ld = cle.Loader(
        io.BytesIO(b"\0" * size),
        main_opts={"backend": "blob", "base_addr": 0, "entry_point": 0, "arch": arch},
    )
    assert (ld.main_object.min_addr, ld.main_object.max_addr) == (0, size - 1)
    return ld


def test_address_space_narrower_than_the_granularity():
    """
    Aligning to the granularity in a 16-bit address space puts the extern object past the end of
    memory, and the load fails with "Ran out of room in address space".
    """
    ld = load_narrow_blob(0x1500)

    extern = ld.extern_object
    assert extern.min_addr > ld.main_object.max_addr
    assert extern.max_addr < 2**ld.main_object.arch.bits
    ld.memory.unpack_word(extern.min_addr)


def test_narrow_address_space_holds_more_objects_than_granules():
    """
    A 16-bit address space does not contain even one default granule, so it holds no object at all
    if the granularity is treated as a constraint.
    """
    ld = load_narrow_blob(0x1500)

    objects = []
    for _ in range(24):
        obj = MockBackend(0x100, arch=ld.main_object.arch)
        ld.dynamic_load(obj)
        objects.append(obj)

    placed = sorted(objects, key=lambda o: o.min_addr)
    assert placed[-1].max_addr < 2**ld.main_object.arch.bits
    for lower, upper in zip(placed, placed[1:]):
        assert lower.max_addr < upper.min_addr
    for obj in objects:
        assert ld.find_object_containing(obj.min_addr) is obj


if __name__ == "__main__":
    test_sparse_main_object()
    test_sparse_main_object_unsorted_program_headers()
    test_rebase_granularity_is_not_a_hard_object_limit()
    test_address_space_narrower_than_the_granularity()
    test_narrow_address_space_holds_more_objects_than_granules()
