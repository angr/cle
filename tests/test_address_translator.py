import nose
import cle

from cle.address_translator import AT


class MockBackend(cle.Backend):
    def __init__(self, linked_base, mapped_base, *nargs, **kwargs):
        super(MockBackend, self).__init__("/dev/zero", *nargs, **kwargs)
        regions = [
            cle.Region(0x000000, 0x8048000, 0x1b2d30, 0x1b2d30),
            cle.Region(0x1b3260, 0x81fc260, 0x002c74, 0x0057bc)
        ]
        self.linked_base = linked_base
        self.mapped_base = mapped_base
        self.segments = cle.Regions(lst=regions)
        self.sections = self.segments
        self.segments._rebase(self.image_base_delta)
        self._is_mapped = True


owner = MockBackend(0x8048000, 0xa000000)


def test_lva_mva_translation():
    nose.tools.assert_equal(AT.from_lva(0x8048000, owner).to_mva(), 0xa000000)
    nose.tools.assert_equal(AT.from_mva(0xa1b9a1b, owner).to_lva(), 0x8201a1b)


def test_va_rva_translation():
    nose.tools.assert_equal(AT.from_rva(0, owner).to_va(), 0xa000000)
    nose.tools.assert_equal(AT.from_va(0xa1b9a1b, owner).to_rva(), 0x1b9a1b)


def test_valid_va_raw_translations():
    nose.tools.assert_equal(AT.from_raw(0x1b3260, owner).to_va(), 0xa1b4260)
    nose.tools.assert_equal(AT.from_va(0xa1b6ed3, owner).to_raw(), 0x1b5ed3)


@nose.tools.raises(TypeError)
def test_invalid_intersegment_raw_va():
    AT.from_raw(0x1b3000, owner).to_va()


def test_invalid_va_raw():
    nose.tools.assert_equal(AT.from_va(0xa1b6ed4, owner).to_raw(), None)


if __name__ == '__main__':
    map(lambda x: x(), filter(lambda o: callable(o) and o.__module__ == '__main__' and o.__name__.startswith("test"), globals().itervalues()))
