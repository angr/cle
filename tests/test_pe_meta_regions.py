from __future__ import annotations

import os
import unittest

import cle
from cle.structs import DataDirectory, MemRegion, MemRegionSort, PointerArray, StringBlob, StructArray

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


# Helper functions


def _find_regions(pe: cle.PE, sort: MemRegionSort) -> list[MemRegion]:
    """Return all top-level meta_regions matching *sort*."""
    return [mr for mr in pe.meta_regions if mr.sort == sort]


def _find_sub_regions(dd: DataDirectory, sort: MemRegionSort) -> list[MemRegion]:
    """Return sub-regions of a DataDirectory matching *sort*."""
    return [sr for sr in dd.sub_regions if sr.sort == sort]


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
        cls.pe_obj: cle.PE = cls.loader.main_object  # type: ignore
        assert isinstance(cls.pe_obj, cle.PE)

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

    def test_import_descriptor_array(self):
        imp = _find_regions(self.pe_obj, MemRegionSort.IMPORT_DIRECTORY)[0]
        assert isinstance(imp, DataDirectory)
        descs = _find_sub_regions(imp, MemRegionSort.IMPORT_DIRECTORY)
        assert len(descs) == 1
        assert isinstance(descs[0], StructArray)
        assert descs[0].entry_size == 20
        assert descs[0].count == 10  # 9 DLLs + null terminator

    def test_import_ilt_arrays(self):
        imp = _find_regions(self.pe_obj, MemRegionSort.IMPORT_DIRECTORY)[0]
        assert isinstance(imp, DataDirectory)
        ilts = _find_sub_regions(imp, MemRegionSort.ILT)
        assert len(ilts) == 9  # one per DLL
        for ilt in ilts:
            assert isinstance(ilt, PointerArray)
            assert ilt.entry_size == 4

    def test_import_hint_name_table(self):
        imp = _find_regions(self.pe_obj, MemRegionSort.IMPORT_DIRECTORY)[0]
        assert isinstance(imp, DataDirectory)
        hnt = _find_sub_regions(imp, MemRegionSort.IMPORT_HINT_NAME_TABLE)
        assert len(hnt) == 1
        assert isinstance(hnt[0], StringBlob)
        assert hnt[0].size > 0

    def test_import_dll_name_strings(self):
        imp = _find_regions(self.pe_obj, MemRegionSort.IMPORT_DIRECTORY)[0]
        assert isinstance(imp, DataDirectory)
        blobs = _find_sub_regions(imp, MemRegionSort.STRING_BLOB)
        assert len(blobs) == 9  # one per DLL

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

    def test_export_sub_regions(self):
        exp = _find_regions(self.pe_obj, MemRegionSort.EXPORT_DIRECTORY)[0]
        assert isinstance(exp, DataDirectory)

        # Header
        headers = _find_sub_regions(exp, MemRegionSort.EXPORT_DIRECTORY)
        assert len(headers) == 1
        assert headers[0].size == 40

        # AddressOfFunctions - 127 x 4B RVAs
        addr_tables = _find_sub_regions(exp, MemRegionSort.EXPORT_ADDR_TABLE)
        assert len(addr_tables) == 1
        assert isinstance(addr_tables[0], PointerArray)
        assert addr_tables[0].count == 127
        assert addr_tables[0].entry_size == 4

        # AddressOfNames - 127 x 4B RVAs
        name_tables = _find_sub_regions(exp, MemRegionSort.EXPORT_NAME_TABLE)
        assert len(name_tables) == 1
        assert isinstance(name_tables[0], PointerArray)
        assert name_tables[0].count == 127

        # AddressOfNameOrdinals - 127 x 2B
        ordinal_tables = _find_sub_regions(exp, MemRegionSort.EXPORT_ORDINAL_TABLE)
        assert len(ordinal_tables) == 1
        assert isinstance(ordinal_tables[0], PointerArray)
        assert ordinal_tables[0].count == 127
        assert ordinal_tables[0].entry_size == 2

        # Name string blob
        blobs = _find_sub_regions(exp, MemRegionSort.STRING_BLOB)
        assert len(blobs) == 1
        assert blobs[0].size > 0

    def test_export_function_hints(self):
        assert len(self.pe_obj.function_hints) == 127

    def test_delay_import_descriptor_array(self):
        dd = _find_regions(self.pe_obj, MemRegionSort.DELAY_IMPORT_DIRECTORY)[0]
        assert isinstance(dd, DataDirectory)
        descs = _find_sub_regions(dd, MemRegionSort.DELAY_IMPORT_DIRECTORY)
        assert len(descs) == 1
        assert isinstance(descs[0], StructArray)
        assert descs[0].entry_size == 32
        assert descs[0].count == 2  # 1 entry + null terminator

    def test_delay_import_int_arrays(self):
        dd = _find_regions(self.pe_obj, MemRegionSort.DELAY_IMPORT_DIRECTORY)[0]
        assert isinstance(dd, DataDirectory)
        ilts = _find_sub_regions(dd, MemRegionSort.ILT)
        assert len(ilts) == 1

    def test_resource_present(self):
        """Data Directory 2 - Resource Directory."""
        resources = _find_regions(self.pe_obj, MemRegionSort.RESOURCE_DIRECTORY)
        assert len(resources) == 1
        res = resources[0]
        assert isinstance(res, DataDirectory)
        assert res.vaddr == self.pe_obj.linked_base + 0x28000
        assert res.size == 3252

    def test_base_reloc_present(self):
        """Data Directory 5 - Base Relocation Table."""
        relocs = _find_regions(self.pe_obj, MemRegionSort.BASE_RELOCATION)
        assert len(relocs) == 1
        reloc = relocs[0]
        assert isinstance(reloc, DataDirectory)
        assert reloc.vaddr == self.pe_obj.linked_base + 0x29000
        assert reloc.size == 5296

    def test_debug_present(self):
        """Data Directory 6 - Debug Directory."""
        debugs = _find_regions(self.pe_obj, MemRegionSort.DEBUG_DIRECTORY)
        assert len(debugs) == 1
        dbg = debugs[0]
        assert isinstance(dbg, DataDirectory)
        assert dbg.vaddr == self.pe_obj.linked_base + 0x26D60
        assert dbg.size == 56

    def test_debug_struct_array(self):
        dbg = _find_regions(self.pe_obj, MemRegionSort.DEBUG_DIRECTORY)[0]
        assert isinstance(dbg, DataDirectory)
        arrays = _find_sub_regions(dbg, MemRegionSort.DEBUG_DIRECTORY)
        assert len(arrays) == 1
        assert isinstance(arrays[0], StructArray)
        assert arrays[0].entry_size == 28
        assert arrays[0].count == 2

    def test_no_exception_directory(self):
        """Directories not present in either test binary should produce no regions."""
        assert len(_find_regions(self.pe_obj, MemRegionSort.EXCEPTION_DIRECTORY)) == 0
        assert len(_find_regions(self.pe_obj, MemRegionSort.TLS_DIRECTORY)) == 0
        assert len(_find_regions(self.pe_obj, MemRegionSort.LOAD_CONFIG_DIRECTORY)) == 0
        assert len(_find_regions(self.pe_obj, MemRegionSort.COM_DESCRIPTOR)) == 0
        assert len(_find_regions(self.pe_obj, MemRegionSort.BOUND_IMPORT_DIRECTORY)) == 0

    def test_flat_regions_export(self):
        exp = _find_regions(self.pe_obj, MemRegionSort.EXPORT_DIRECTORY)[0]
        assert isinstance(exp, DataDirectory)
        flat = exp.flat_regions()
        assert len(flat) == len(exp.sub_regions)
        assert flat == list(exp.sub_regions)


if __name__ == "__main__":
    unittest.main()
