import pefile
import struct
import logging

from ..relocations import Relocation
from ...address_translator import AT

l = logging.getLogger('cle.backends.pe.reloc')

# Reference: https://msdn.microsoft.com/en-us/library/ms809762.aspx
class WinReloc(Relocation):
    """
    Represents a relocation for the PE format.
    """
    def __init__(self, owner, symbol, addr, resolvewith, reloc_type=None, next_rva=None):
        super(WinReloc, self).__init__(owner, symbol, addr, None)
        self.resolvewith = resolvewith
        self.reloc_type = reloc_type
        self.next_rva = next_rva # only used for IMAGE_REL_BASED_HIGHADJ

    def resolve_symbol(self, solist, bypass_compatibility=False):
        if not bypass_compatibility:
            solist = [x for x in solist if self.resolvewith.lower() == x.provides]
        return super(WinReloc, self).resolve_symbol(solist)

    @property
    def value(self):
        if self.resolved:
            return self.resolvedby.rebased_addr

    def relocate(self, solist, bypass_compatibility=False):
        # no symbol -> this is a relocation described in the DIRECTORY_ENTRY_BASERELOC table
        if self.symbol is None:
            if self.reloc_type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_ABSOLUTE']:
                # no work required
                pass
            elif self.reloc_type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW']:
                org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 4))
                org_value = struct.unpack('<I', org_bytes)[0]
                rebased_value = AT.from_lva(org_value, self.owner_obj).to_mva()
                rebased_bytes = struct.pack('<I', rebased_value % 2**32)
                self.owner_obj.memory.write_bytes(self.relative_addr, rebased_bytes)
            elif self.reloc_type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']:
                org_bytes = ''.join(self.owner_obj.memory.read_bytes(self.relative_addr, 8))
                org_value = struct.unpack('<Q', org_bytes)[0]
                rebased_value = AT.from_lva(org_value, self.owner_obj).to_mva()
                rebased_bytes = struct.pack('<Q', rebased_value)
                self.owner_obj.memory.write_bytes(self.relative_addr, rebased_bytes)
            else:
                l.warning('PE contains unimplemented relocation type %d', self.reloc_type)
        else:
            return super(WinReloc, self).relocate(solist, bypass_compatibility)
