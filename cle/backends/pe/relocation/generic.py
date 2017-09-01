import struct
import logging
from .pereloc import PEReloc
from ....address_translator import AT

l = logging.getLogger('cle.backends.pe.relocation.generic')

class DllImport(PEReloc):
    """
    There's nothing special to be done for DLL imports but this class
    provides a unique name to the relocation type.
    """
    pass

class IMAGE_REL_BASED_ABSOLUTE(PEReloc):
    pass

class IMAGE_REL_BASED_HIGHADJ(PEReloc):
    def __init__(self, owner, addr, next_rva):
        super(IMAGE_REL_BASED_HIGHADJ, self).__init__(owner, None, addr)
        self.next_rva = next_rva
    @property
    def value(self):
        """
        In all the other cases, we can ignore the relocation difference part of the
        calculation because we simply use to_mva() to get our rebased address. In this
        case, however, we have to adjust the un-rebased address first.
        """
        org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 2))
        org_value = struct.unpack('<I', org_bytes)[0]
        adjusted_value = (org_value << 16) + self.next_rva
        adjusted_value = (AT.from_lva(adjusted_value, self.owner_obj) & 0xffff0000) >> 16
        adjusted_bytes = struct.pack('<I', adjusted_value)
        return adjusted_bytes

class IMAGE_REL_BASED_HIGHLOW(PEReloc):
    @property
    def value(self):
        org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 4))
        org_value = struct.unpack('<I', org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner_obj).to_mva()
        rebased_bytes = struct.pack('<I', rebased_value)
        return rebased_bytes

class IMAGE_REL_BASED_DIR64(PEReloc):
    @property
    def value(self):
        org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 8))
        org_value = struct.unpack('<Q', org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner_obj).to_mva()
        rebased_bytes = struct.pack('<Q', rebased_value)
        return rebased_bytes

class IMAGE_REL_BASED_HIGH(PEReloc):
    @property
    def value(self):
        org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 2))
        org_value = struct.unpack('<H', org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner_obj).to_mva()
        adjusted_value = (rebased_value >> 16) & 0xffff
        adjusted_bytes = struct.pack('<H', adjusted_value)
        return adjusted_bytes

class IMAGE_REL_BASED_LOW(PEReloc):
    @property
    def value(self):
        org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 2))
        org_value = struct.unpack('<H', org_bytes)[0]
        rebased_value = AT.from_lva(org_value, self.owner_obj).to_mva()
        adjusted_value = rebased_value & 0x0000FFFF
        adjusted_bytes = struct.pack('<H', adjusted_value)
        return adjusted_bytes
