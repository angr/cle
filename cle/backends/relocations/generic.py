from ...errors import CLEOperationError
from . import Relocation
import struct

import logging
l = logging.getLogger('cle.relocations.generic')

class GenericAbsoluteReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr

class GenericAbsoluteAddendReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend

class GenericPCRelativeAddendReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend - self.rebased_addr

class GenericJumpslotReloc(Relocation):
    @property
    def value(self):
        if self.is_rela:
            return self.resolvedby.rebased_addr + self.addend
        else:
            return self.resolvedby.rebased_addr

class GenericRelativeReloc(Relocation):
    @property
    def value(self):
        return self.owner_obj.rebase_addr + self.addend

    def resolve_symbol(self, solist, bypass_compatibility=False):
        self.resolve(None)
        return True

class GenericCopyReloc(Relocation):
    @property
    def value(self):
        return self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr)

class MipsGlobalReloc(GenericAbsoluteReloc):
    pass

class MipsLocalReloc(Relocation):
    def relocate(self, solist, bypass_compatibility=False): # pylint: disable=unused-argument
        if self.owner_obj.rebase_addr == 0:
            self.resolve(None)
            return True                     # don't touch local relocations on the main bin
        delta = self.owner_obj.rebase_addr - self.owner_obj._dynamic['DT_MIPS_BASE_ADDRESS']
        if delta == 0:
            self.resolve(None)
            return True
        val = self.owner_obj.memory.read_addr_at(self.addr)
        newval = val + delta
        self.owner_obj.memory.write_addr_at(self.addr, newval)
        self.resolve(None)
        return True

class RelocTruncate32Mixin(object):
    """
    A mix-in class for relocations that cover a 32-bit field regardless of the architecture's address word length.
    """

    # If True, 32-bit truncated value must equal to its original when zero-extended
    check_zero_extend = False

    # If True, 32-bit truncated value must equal to its original when sign-extended
    check_sign_extend = False

    def relocate(self, solist, bypass_compatibility=False): # pylint: disable=unused-argument
        if not self.resolve_symbol(solist):
            return False

        arch_bits = self.owner_obj.arch.bits
        assert arch_bits >= 32            # 16-bit makes no sense here

        val = self.value % (2**arch_bits)   # we must truncate it to native range first

        if (self.check_zero_extend and val >> 32 != 0 or
                self.check_sign_extend and val >> 32 != ((1 << (arch_bits - 32)) - 1)
                                                        if ((val >> 31) & 1) == 1 else 0):
            raise CLEOperationError("relocation truncated to fit: %s; consider making"
                                    " relevant addresses fit in the 32-bit address space." % self.__class__.__name__)

        by = struct.pack(self.owner_obj.arch.struct_fmt(32), val % (2**32))
        self.owner_obj.memory.write_bytes(self.dest_addr, by)
