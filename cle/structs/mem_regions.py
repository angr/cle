from __future__ import annotations

from enum import Enum


class MemRegionSort(Enum):
    """Semantic tag for a metadata memory region."""

    # Generic
    POINTER_ARRAY = "pointer-array"
    STRUCT_ARRAY = "struct-array"
    STRING_BLOB = "string-blob"
    DATA = "data"

    # PE-specific
    IAT = "iat"
    ILT = "ilt"
    EXPORT_DIRECTORY = "export-directory"
    EXPORT_ADDR_TABLE = "export-addr-table"
    EXPORT_NAME_TABLE = "export-name-table"
    EXPORT_ORDINAL_TABLE = "export-ordinal-table"
    IMPORT_DIRECTORY = "import-directory"
    IMPORT_HINT_NAME_TABLE = "import-hint-name-table"
    DELAY_IMPORT_DIRECTORY = "delay-import-directory"


class MemRegion:
    """A contiguous region of metadata in memory."""

    __slots__ = ("vaddr", "size", "sort")

    def __init__(self, vaddr: int, size: int, sort: MemRegionSort):
        self.vaddr = vaddr
        self.size = size
        self.sort = sort

    def __repr__(self):
        return f"<MemRegion {self.sort.name} @ {self.vaddr:#x}, {self.size} bytes>"


class PointerArray(MemRegion):
    """An array of fixed-size pointer entries."""

    __slots__ = ("entry_size", "count")

    def __init__(self, vaddr: int, entry_size: int, count: int, sort: MemRegionSort = MemRegionSort.POINTER_ARRAY):
        super().__init__(vaddr, entry_size * count, sort)
        self.entry_size = entry_size
        self.count = count

    def __repr__(self):
        return f"<PointerArray {self.sort.name} @ {self.vaddr:#x}, {self.count} x {self.entry_size}B>"


class StructArray(MemRegion):
    """An array of fixed-size structures."""

    __slots__ = ("entry_size", "count")

    def __init__(self, vaddr: int, entry_size: int, count: int, sort: MemRegionSort = MemRegionSort.STRUCT_ARRAY):
        super().__init__(vaddr, entry_size * count, sort)
        self.entry_size = entry_size
        self.count = count

    def __repr__(self):
        return f"<StructArray {self.sort.name} @ {self.vaddr:#x}, {self.count} x {self.entry_size}B>"


class StringBlob(MemRegion):
    """A blob of packed null-terminated strings."""

    __slots__ = ()

    def __init__(self, vaddr: int, size: int, sort: MemRegionSort = MemRegionSort.STRING_BLOB):
        super().__init__(vaddr, size, sort)

    def __repr__(self):
        return f"<StringBlob {self.sort.name} @ {self.vaddr:#x}, {self.size} bytes>"


class DataDirectory(MemRegion):
    """A composite region made up of sub-regions."""

    __slots__ = ("sub_regions",)

    def __init__(self, vaddr: int, size: int, sort: MemRegionSort, sub_regions: list[MemRegion] | None = None):
        super().__init__(vaddr, size, sort)
        self.sub_regions = sub_regions or []

    def __repr__(self):
        return (
            f"<DataDirectory {self.sort.name} @ {self.vaddr:#x}, {self.size} bytes, "
            f"{len(self.sub_regions)} sub-regions>"
        )

    def flat_regions(self) -> list[MemRegion]:
        """Return all sub-regions flattened (non-recursive for now)."""
        return list(self.sub_regions)
