from __future__ import annotations

import os

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


def test_the_main_binary_base_is_not_handed_out_twice():
    """
    A container backend loads its children through the loader, and a child can be marked as the
    main binary: a universal Mach-O marks every slice it loads, because a Mach-O executable
    refuses to load as anything else. The position-independent main binary has a fixed base
    address, so the second such object was placed on top of the first.
    """
    path = os.path.join(TEST_BASE, "tests", "i386", "manysum")
    ld = cle.Loader(path, auto_load_libs=False)

    first = MockBackend(0x1000, arch=ld.main_object.arch, is_main_bin=True)
    second = MockBackend(0x1000, arch=ld.main_object.arch, is_main_bin=True)
    ld.dynamic_load(first)
    ld.dynamic_load(second)

    assert first.mapped_base == 0x400000
    assert second.min_addr > first.max_addr


if __name__ == "__main__":
    test_sparse_main_object()
    test_sparse_main_object_unsorted_program_headers()
    test_rebase_granularity_is_not_a_hard_object_limit()
    test_the_main_binary_base_is_not_handed_out_twice()
