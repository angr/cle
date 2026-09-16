from __future__ import annotations

import os

import pytest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

#: the key tests/x86_64/1after909.cart was packed with
CART_KEY = b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class MockBackend(cle.backends.Backend):  # pylint: disable=missing-class-docstring
    def __init__(self, linked_base, size, pic=True, **kwargs):
        super().__init__("/dev/zero", None, **kwargs)
        self.mapped_base = self.linked_base = linked_base
        self.size = size
        self.pic = pic

    @property
    def max_addr(self):
        return self.mapped_base + self.size - 1


def test_overlap():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests/i386/manysum")
    ld = cle.Loader(filename, auto_load_libs=False)
    assert ld.main_object.linked_base == 0x8048000
    assert ld.main_object.min_addr == 0x8048000

    obj1 = MockBackend(0x8047000, 0x2000, arch=ld.main_object.arch)
    obj2 = MockBackend(0x8047000, 0x1000, arch=ld.main_object.arch)

    ld.dynamic_load(obj1)
    ld.dynamic_load(obj2)

    assert obj2.mapped_base == 0x8047000
    assert obj1.mapped_base > 0x8048000


def test_outer_object_does_not_occupy_address_space():
    """
    An outer object backs no memory and reports a one-byte span at whatever base it was placed at. That byte must not
    keep the object it unpacks from being mapped there. The CaRT wrapper is mapped first and keeps its linked base of
    0, so a position-dependent child linked at 0 was refused for overlapping its own container.
    """
    cartfile = os.path.join(TEST_BASE, "tests", "x86_64", "1after909.cart")
    ld = cle.Loader(
        cartfile,
        auto_load_libs=False,
        main_opts={"arc4_key": CART_KEY},
        lib_opts={
            cle.backends.CARTFile.get_unpacked_name(cartfile): {
                "backend": "blob",
                "arch": "amd64",
                "base_addr": 0,
            }
        },
    )

    (container,) = (o for o in ld.all_objects if o.is_outer)
    assert isinstance(container, cle.backends.CARTFile)
    # the container claims exactly the address its child is linked at
    assert container.min_addr == container.max_addr == 0

    (child,) = container.child_objects
    assert child is ld.main_object
    assert not child.pic
    assert child.mapped_base == 0
    # and the child, not the container, is what answers for that address
    assert ld.find_object_containing(0) is child
    with open(os.path.join(TEST_BASE, "tests", "x86_64", "1after909"), "rb") as fp:
        assert ld.memory.load(0, 16) == fp.read(16)


def test_outer_object_does_not_move_rebased_objects():
    """
    The free space the loader rebases into starts at 0 when the main object reaches into the top half of the address
    space, which is where an outer object mapped at its linked base of 0 sits. Counting that one byte pushed everything
    the loader rebases up by a full granule, so a wrapped binary came out laid out differently from the same binary
    unwrapped.
    """
    plain_path = os.path.join(TEST_BASE, "tests", "x86_64", "1after909")
    cartfile = os.path.join(TEST_BASE, "tests", "x86_64", "1after909.cart")
    # loading the image high is what puts the free space, and so the container's byte, below the main object
    blob_opts = {"backend": "blob", "arch": "amd64", "base_addr": 0xFFFFFFFF80000000}

    plain = cle.Loader(plain_path, auto_load_libs=False, main_opts=dict(blob_opts))
    wrapped = cle.Loader(
        cartfile,
        auto_load_libs=False,
        main_opts={"arc4_key": CART_KEY},
        lib_opts={cle.backends.CARTFile.get_unpacked_name(cartfile): dict(blob_opts)},
    )

    (container,) = (o for o in wrapped.all_objects if o.is_outer)
    assert container.min_addr == container.max_addr == 0
    assert wrapped.main_object.min_addr == plain.main_object.min_addr

    def rebase(ld):
        obj = MockBackend(0, 0x1000, arch=ld.main_object.arch)
        ld.dynamic_load(obj)
        return obj.mapped_base

    # Which address the loader hands out is its own placement policy and moves with it -- cle#765 takes
    # the invented objects off the null page -- so what this test owns is that wrapping does not change it.
    assert rebase(wrapped) == rebase(plain)


def test_memoryless_region_still_reserves_address_space():
    """
    Backing no memory is not what keeps an object out of the address space: a NamedRegion has no memory on purpose and
    exists to reserve a range cle has no data for, so it has to keep taking part in the overlap check.
    """
    ld = cle.Loader(os.path.join(TEST_BASE, "tests", "i386", "manysum"), auto_load_libs=False)

    region = cle.NamedRegion("mmio", 0x8000000, 0x8001000, arch=ld.main_object.arch)
    assert not region.has_memory
    assert not region.is_outer
    ld.dynamic_load(region)

    with pytest.raises(cle.CLEError, match="would overlap mmio"):
        ld.dynamic_load(MockBackend(0x8000000, 0x1000, pic=False, arch=ld.main_object.arch))


def test_placement_past_the_end_of_the_address_space():
    """
    An object that does not fit in the architecture's address space is refused before any overlap check, so the error
    has to name the address space rather than an object that is in the way.
    """
    with pytest.raises(cle.CLEError, match="past the end of the 32-bit address space"):
        cle.Loader(
            os.path.join(TEST_BASE, "tests", "i386", "manysum"),
            main_opts={"backend": "blob", "arch": "i386", "base_addr": 0xFFFFF000},
        )


if __name__ == "__main__":
    test_overlap()
    test_outer_object_does_not_occupy_address_space()
    test_outer_object_does_not_move_rebased_objects()
    test_memoryless_region_still_reserves_address_space()
    test_placement_past_the_end_of_the_address_space()
