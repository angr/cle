from __future__ import annotations

import os

import archinfo

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
        # the main object's memory is one backer spanning 0xf800 to 0xfff00fff, so anything
        # placed inside that span is unreachable
        assert obj.max_addr < 0xF800 or obj.min_addr > 0xFFF00FFF
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


def load_blob(name, arch, base_addr):
    path = os.path.join(TEST_BASE, "tests", *name)
    return cle.Loader(path, auto_load_libs=False, main_opts={"backend": "blob", "arch": arch, "base_addr": base_addr})


def test_image_in_the_top_half_leaves_the_null_page_free():
    """
    An image based at 0x90000000 has free space above it and below it. The extern object may
    go either way, but not over address 0, which every uninitialized pointer in the target
    reads as.
    """
    ld = load_blob(("armel", "i2c_master_read-nucleol152re.bin"), "ARMEL", 0x90000000)
    assert ld.main_object.max_addr >= 2**31

    extern = ld.extern_object
    assert extern.min_addr > ld.main_object.max_addr
    assert ld.find_object_containing(0) is None


def test_narrow_address_space_leaves_the_null_page_free():
    """
    A 16-bit image at 0x4000 leaves 48 KB above it, and a z80 reaches address 0 with RST and
    a direct-page call, so the extern object must not answer for those addresses.
    """
    ld = load_blob(("i386", "rcr_test"), archinfo.ArchPcode("z80:LE:16:default"), 0x4000)

    extern = ld.extern_object
    assert extern.min_addr > ld.main_object.max_addr
    assert extern.max_addr < 2**16
    assert ld.find_object_containing(0) is None
    ld.memory.unpack_word(extern.min_addr, size=1)


def test_null_page_is_used_when_the_address_space_has_nothing_else():
    """
    Keeping the null page free is a preference, not a constraint. A 16-bit address space with
    everything else taken must still place an object rather than fail the load.
    """
    ld = load_blob(("i386", "rcr_test"), archinfo.ArchPcode("z80:LE:16:default"), 0x4000)
    arch = ld.main_object.arch
    main = ld.main_object

    above = MockBackend(2**16 - (main.max_addr + 1), arch=arch)
    below = MockBackend(main.min_addr - 0x1000, arch=arch)
    for obj in (above, below):
        ld.dynamic_load(obj)
    assert (above.min_addr, above.max_addr) == (main.max_addr + 1, 2**16 - 1)
    assert (below.min_addr, below.max_addr) == (0x1000, main.min_addr - 1)

    last = MockBackend(0x100, arch=arch)
    ld.dynamic_load(last)
    assert last.min_addr == 0


if __name__ == "__main__":
    test_sparse_main_object()
    test_sparse_main_object_unsorted_program_headers()
    test_rebase_granularity_is_not_a_hard_object_limit()
    test_image_in_the_top_half_leaves_the_null_page_free()
    test_narrow_address_space_leaves_the_null_page_free()
    test_null_page_is_used_when_the_address_space_has_nothing_else()
