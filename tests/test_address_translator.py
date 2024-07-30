# pylint: disable=missing-class-docstring
from __future__ import annotations

import unittest

import cle
from cle.address_translator import AT


class MockBackend(cle.Backend):
    def __init__(self, linked_base, mapped_base, *nargs, **kwargs):
        super().__init__("/dev/zero", None, *nargs, **kwargs)
        regions = [
            cle.Region(0x000000, 0x8048000, 0x1B2D30, 0x1B2D30),
            cle.Region(0x1B3260, 0x81FC260, 0x002C74, 0x0057BC),
        ]
        self.linked_base = linked_base
        self.mapped_base = mapped_base
        self.segments = cle.Regions(lst=regions)
        self.sections = self.segments
        self.segments._rebase(self.image_base_delta)
        self._is_mapped = True


class TestAddressTranslator(unittest.TestCase):
    def setUp(self):
        self.owner = MockBackend(0x8048000, 0xA000000)

    def test_lva_mva_translation(self):
        assert AT.from_lva(0x8048000, self.owner).to_mva() == 0xA000000
        assert AT.from_mva(0xA1B9A1B, self.owner).to_lva() == 0x8201A1B

    def test_va_rva_translation(self):
        assert AT.from_rva(0, self.owner).to_va() == 0xA000000
        assert AT.from_va(0xA1B9A1B, self.owner).to_rva() == 0x1B9A1B

    def test_valid_va_raw_translations(self):
        assert AT.from_raw(0x1B3260, self.owner).to_va() == 0xA1B4260
        assert AT.from_va(0xA1B6ED3, self.owner).to_raw() == 0x1B5ED3

    def test_invalid_intersegment_raw_va(self):
        with self.assertRaises(TypeError):
            AT.from_raw(0x1B3000, self.owner).to_va()

    def test_invalid_va_raw(self):
        assert AT.from_va(0xA1B6ED4, self.owner).to_raw() is None


if __name__ == "__main__":
    unittest.main()
