from __future__ import annotations

import logging
import struct

from cle.address_translator import AT

from .pereloc import PEReloc

log = logging.getLogger(name=__name__)

__all__ = [
    "DllImport",
    "IMAGE_REL_BASED_ABSOLUTE",
    "IMAGE_REL_BASED_HIGHADJ",
    "IMAGE_REL_BASED_HIGHLOW",
    "IMAGE_REL_BASED_DIR64",
    "IMAGE_REL_BASED_HIGH",
    "IMAGE_REL_BASED_LOW",
]


class DllImport(PEReloc):
    """
    There's nothing special to be done for DLL imports but this class
    provides a unique name to the relocation type.
    """

    __slots__ = ()


class IMAGE_REL_BASED_ABSOLUTE(PEReloc):
    __slots__ = ()

    def relocate(self):
        pass


class IMAGE_REL_BASED_HIGHADJ(PEReloc):
    """
    Adjusts the high half of a 32-bit value whose low half sits in the following relocation slot; ``next_rva`` holds
    that low half.
    """

    __slots__ = ("next_rva",)

    def __init__(self, owner, addr, next_rva):
        super().__init__(owner, None, addr)
        self.next_rva = next_rva

    @property
    def value(self):
        org_high = struct.unpack("<H", self.owner.memory.load(self.relative_addr, 2))[0]
        low = self.next_rva - 0x10000 if self.next_rva & 0x8000 else self.next_rva
        rebased = AT.from_lva((org_high << 16) + low, self.owner).to_mva()
        # round to the nearest high half, as the Windows loader does
        return struct.pack("<H", ((rebased + 0x8000) >> 16) & 0xFFFF)


class IMAGE_REL_BASED_HIGHLOW(PEReloc):
    __slots__ = ()

    @property
    def value(self):
        org_bytes = self.owner.memory.load(self.relative_addr, 4)
        org_value = struct.unpack("<I", org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner).to_mva()
        rebased_bytes = struct.pack("<I", rebased_value & 0xFFFFFFFF)
        return rebased_bytes


class IMAGE_REL_BASED_DIR64(PEReloc):
    __slots__ = ()

    @property
    def value(self):
        org_bytes = self.owner.memory.load(self.relative_addr, 8)
        org_value = struct.unpack("<Q", org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner).to_mva()
        if rebased_value < 0 or rebased_value >= 0x10000000000000000:
            log.error(
                "Incorrect rebased address %x found at %s. Maybe the relocation table is broken.",
                rebased_value,
                self.owner,
            )
            return None
        rebased_bytes = struct.pack("<Q", rebased_value)
        return rebased_bytes


class IMAGE_REL_BASED_HIGH(PEReloc):
    __slots__ = ()

    @property
    def value(self):
        org_bytes = self.owner.memory.load(self.relative_addr, 2)
        org_value = struct.unpack("<H", org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner).to_mva()
        adjusted_value = (rebased_value >> 16) & 0xFFFF
        adjusted_bytes = struct.pack("<H", adjusted_value)
        return adjusted_bytes


class IMAGE_REL_BASED_LOW(PEReloc):
    __slots__ = ()

    @property
    def value(self):
        org_bytes = self.owner.memory.load(self.relative_addr, 2)
        org_value = struct.unpack("<H", org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner).to_mva()
        adjusted_value = rebased_value & 0x0000FFFF
        adjusted_bytes = struct.pack("<H", adjusted_value)
        return adjusted_bytes


relocation_table_generic = {
    1: IMAGE_REL_BASED_HIGH,
    2: IMAGE_REL_BASED_LOW,
    3: IMAGE_REL_BASED_HIGHLOW,
    4: IMAGE_REL_BASED_HIGHADJ,
    10: IMAGE_REL_BASED_DIR64,
}
