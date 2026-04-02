from __future__ import annotations

import logging
import struct
from io import BytesIO

from .backend import Backend, register_backend

log = logging.getLogger(__name__)

# Mach-O fat binary magic numbers
FAT_MAGIC = 0xCAFEBABE  # Universal Binary 1 (32-bit fat_arch)
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF  # Universal Binary 2 (64-bit fat_arch)
FAT_CIGAM_64 = 0xBFBAFECA

# Mach-O CPU type constants (from mach/machine.h)
CPU_TYPE_NAMES = {
    0x100000C: "aarch64",
    0xC: "arm",
    0x7: "x86",
    0x1000007: "x64",
}


class Universal2(Backend):
    """Backend for loading macOS Universal Binary 2 (fat) files.

    A Universal Binary is a container that packages multiple architecture-specific
    Mach-O binaries into a single file. Universal Binary 2 uses 64-bit offsets
    in the fat_arch structures.

    This backend also supports the original Universal Binary 1 format (32-bit offsets).

    To load only a specific architecture slice, pass ``arch`` in the loader options::

        cle.Loader("path/to/universal", main_opts={"arch": "aarch64"})
    """

    is_default = True
    is_outer = True

    @classmethod
    def is_compatible(cls, stream):
        stream.seek(0)
        data = stream.read(4)
        if len(data) < 4:
            return False
        magic = struct.unpack(">I", data)[0]
        return magic in (FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64)

    def __init__(self, *args, arch=None, **kwargs):
        super().__init__(*args, **kwargs)

        # Track whether we are the main binary so we can propagate this to children
        self._is_main_universal = self.loader._main_object is None

        # hack: same as StaticArchive - prevent children from becoming main_object
        if self._is_main_universal:
            self.loader._main_object = self

        self._binary_stream.seek(0)
        magic_bytes = self._binary_stream.read(4)
        magic = struct.unpack(">I", magic_bytes)[0]

        # Determine endianness and format
        if magic in (FAT_MAGIC_64, FAT_MAGIC):
            endian = ">"
        else:
            endian = "<"

        is_fat64 = magic in (FAT_MAGIC_64, FAT_CIGAM_64)

        # Parse fat_header: magic (already read) + nfat_arch
        nfat_arch = struct.unpack(endian + "I", self._binary_stream.read(4))[0]

        # Parse fat_arch entries: (cputype, cpusubtype, offset, size, align)
        self._fat_arches = []
        slices = []
        for _ in range(nfat_arch):
            if is_fat64:
                # fat_arch_64: cputype(4) cpusubtype(4) offset(8) size(8) align(4) reserved(4)
                cputype, cpusubtype, offset, size, align, _reserved = struct.unpack(
                    endian + "IIQQiI", self._binary_stream.read(32)
                )
            else:
                # fat_arch: cputype(4) cpusubtype(4) offset(4) size(4) align(4)
                cputype, cpusubtype, offset, size, align = struct.unpack(
                    endian + "IIIIi", self._binary_stream.read(20)
                )
            slices.append((cputype, cpusubtype, offset, size, align))
        self._fat_arches = list(slices)

        # Filter to requested architecture if specified
        if arch is not None:
            target_arch = arch.lower()
            filtered = []
            for cputype, cpusubtype, offset, size, align in slices:
                arch_name = CPU_TYPE_NAMES.get(cputype)
                if arch_name and arch_name.lower() == target_arch:
                    filtered.append((cputype, cpusubtype, offset, size, align))
            if not filtered:
                available = [CPU_TYPE_NAMES.get(s[0], f"unknown(0x{s[0]:X})") for s in slices]
                raise KeyError(
                    f"Architecture {arch!r} not found in universal binary. "
                    f"Available architectures: {available}"
                )
            slices = filtered

        # Load each slice using _load_object_isolated.
        # Unlike StaticArchive (where children are .o files), universal binary slices
        # may be MH_EXECUTE binaries that require is_main_bin=True. We temporarily
        # unset _main_object before each child load so MachO's MH_EXECUTE assertion
        # passes, then restore it immediately after.
        for cputype, cpusubtype, offset, size, align in slices:
            arch_name = CPU_TYPE_NAMES.get(cputype, f"unknown_0x{cputype:X}")
            self._binary_stream.seek(offset)
            slice_data = self._binary_stream.read(size)
            slice_stream = BytesIO(slice_data)
            slice_stream.name = f"{self.binary_basename}[{arch_name}]"

            if self._is_main_universal:
                self.loader._main_object = None
            child = self.loader._load_object_isolated(slice_stream)
            if self._is_main_universal:
                self.loader._main_object = self
            child.binary = child.binary_basename = f"{self.binary_basename}[{arch_name}]"
            child.parent_object = self
            self.child_objects.append(child)

        if self.child_objects:
            self._arch = self.child_objects[0].arch
        else:
            log.warning("Loaded empty universal binary?")

        self.has_memory = False
        self.pic = True

        # hack pt. 2
        if self.loader._main_object is self:
            self.loader._main_object = None

    @property
    def available_arches(self):
        """Return the list of architecture names present in the universal binary's fat header."""
        return [CPU_TYPE_NAMES.get(cputype, f"unknown(0x{cputype:X})") for cputype, *_ in self._fat_arches]

    @property
    def slices(self):
        """Return the child Mach-O objects (one per architecture slice)."""
        return list(self.child_objects)


register_backend("Universal2", Universal2)
