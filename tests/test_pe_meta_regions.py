from __future__ import annotations

import os
import unittest

import cle
from cle.structs import DataDirectory, MemRegionSort, PointerArray

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


class TestPEMetaRegions(unittest.TestCase):
    """Test that cle's PE backend correctly exposes meta_regions."""

    @classmethod
    def setUpClass(cls):
        TEST_BINARY = os.path.join(
            TEST_BASE, "tests", "i386", "windows", "3995b0522f1daaf8dc1341f87f34a1897ae8988e8dfa1cbe0bc98943385f4c38"
        )

        # Known layout of the test binary (PE32, ImageBase=0x76be0000):
        # .text section: RVA 0x1000..0x26d98
        # IAT (dir 12):        RVA 0x1000, size 0x4d0  -> inside .text
        # Export dir (dir 0):  RVA 0x3440, size 0x117d  -> inside .text
        # Import dir (dir 1):  RVA 0x24f90, size 0xc8   -> inside .text
        # Delay import (dir 13): RVA 0x24ef8, size 0x40 -> inside .text

        cls._image_base = 0x76BE0000

        cls.loader = cle.Loader(TEST_BINARY, auto_load_libs=False)
        cls.pe_obj = cls.loader.main_object

    def test_meta_regions_populated(self):
        """meta_regions should be non-empty for a PE with import/export tables."""
        assert len(self.pe_obj.meta_regions) > 0

    def test_iat_region_exists(self):
        """IAT should be present as a PointerArray with sort IAT."""
        iat_regions = [
            r
            for r in self.pe_obj.meta_regions
            if not isinstance(r, DataDirectory) and isinstance(r, PointerArray) and r.sort == MemRegionSort.IAT
        ]
        assert len(iat_regions) == 1
        iat = iat_regions[0]
        assert iat.vaddr == self._image_base + 0x1000
        assert iat.size == 0x4D0
        assert iat.entry_size == 4

    def test_export_directory_exists(self):
        """Export directory should be present as a DataDirectory."""
        exp_dirs = [
            r
            for r in self.pe_obj.meta_regions
            if isinstance(r, DataDirectory) and r.sort == MemRegionSort.EXPORT_DIRECTORY
        ]
        assert len(exp_dirs) == 1
        exp = exp_dirs[0]
        assert exp.vaddr == self._image_base + 0x3440
        assert exp.size == 0x117D
        # Should have sub-regions: header, func table, name table, ordinal table, name strings
        assert len(exp.sub_regions) >= 4

    def test_import_directory_exists(self):
        """Import directory should be present as a DataDirectory."""
        imp_dirs = [
            r
            for r in self.pe_obj.meta_regions
            if isinstance(r, DataDirectory) and r.sort == MemRegionSort.IMPORT_DIRECTORY
        ]
        assert len(imp_dirs) == 1
        imp = imp_dirs[0]
        assert imp.vaddr == self._image_base + 0x24F90

    def test_delay_import_directory_exists(self):
        """Delay import directory should be present."""
        delay_dirs = [
            r
            for r in self.pe_obj.meta_regions
            if isinstance(r, DataDirectory) and r.sort == MemRegionSort.DELAY_IMPORT_DIRECTORY
        ]
        assert len(delay_dirs) == 1
        delay = delay_dirs[0]
        assert delay.vaddr == self._image_base + 0x24EF8


if __name__ == "__main__":
    unittest.main()
