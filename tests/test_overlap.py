import os

import cle


class MockBackend(cle.backends.Backend):  # pylint: disable=missing-class-docstring
    def __init__(self, linked_base, size, **kwargs):
        super().__init__("/dev/zero", None, **kwargs)
        self.mapped_base = self.linked_base = linked_base
        self.size = size
        self.pic = True

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


if __name__ == "__main__":
    test_overlap()
