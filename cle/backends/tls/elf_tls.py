import struct

from ...errors import CLEError
from . import TLSObject, InternalTLSRelocation

TLS_BLOCK_ALIGN = 0x10
TLS_TOTAL_HEAD_SIZE = 0x4000
TLS_HEAD_ALIGN = 0x10000

def roundup(val, to=TLS_BLOCK_ALIGN):
    return val - 1 + (to - ((val - 1) % to))


class ELFTLSObject(TLSObject):
    """
    This class is used when parsing the Thread Local Storage of an ELF binary. It heavily uses the TLSArchInfo
    namedtuple from archinfo.

    ELF TLS is implemented based on the following documents:

        - https://www.uclibc.org/docs/tls.pdf
        - https://www.uclibc.org/docs/tls-ppc.txt
        - https://www.uclibc.org/docs/tls-ppc64.txt
        - https://www.linux-mips.org/wiki/NPTL
    """
    def __init__(self, loader, max_data=0x8000, max_modules=256):
        super(ELFTLSObject, self).__init__(loader, max_modules=max_modules)
        self.next_module_id = 1
        self.total_blocks_size = 0
        self.max_data = max_data
        self.modules = []
        self._max_addr = 0

        if self.arch.elf_tls.variant == 1:
            # variant 1: memory is laid out like so:
            # [header][module data][dtv]
            #         ^ thread pointer
            self.tcb_offset = TLS_TOTAL_HEAD_SIZE - self.arch.elf_tls.tcbhead_size
            self.tp_offset = TLS_TOTAL_HEAD_SIZE    # CRITICAL DIFFERENCE FROM THE DOC - variant 1 seems to expect the thread pointer points to the end of the TCB
            self.dtv_offset = TLS_TOTAL_HEAD_SIZE + self.max_data + 2*self.arch.bytes
            self._max_addr = self.dtv_offset + 2*self.arch.bytes*max_modules
            self.memory.add_backer(0, bytes(TLS_TOTAL_HEAD_SIZE))
        else:
            # variant 2: memory is laid out like so:
            # [module data][header][dtv]
            #              ^ thread pointer
            self.tcb_offset = roundup(self.max_data, TLS_HEAD_ALIGN)
            self.tp_offset = roundup(self.max_data, TLS_HEAD_ALIGN)
            self.dtv_offset = self.tp_offset + TLS_TOTAL_HEAD_SIZE + 2*self.arch.bytes
            self._max_addr = self.dtv_offset + 2*self.arch.bytes*max_modules
            self.memory.add_backer(self.tp_offset, bytes(TLS_TOTAL_HEAD_SIZE))

        self.memory.add_backer(self.dtv_offset - 2*self.arch.bytes, bytes(2*self.arch.bytes*max_modules + 2*self.arch.bytes))

        # Set the appropriate pointers in the tcbhead
        for off in self.arch.elf_tls.head_offsets:
            self.drop_int(self.tp_offset, off + self.tcb_offset, True)
        for off in self.arch.elf_tls.dtv_offsets:
            self.drop_int(self.dtv_offset, off + self.tcb_offset, True)
        for off in self.arch.elf_tls.pthread_offsets:
            self.drop_int(self.tp_offset, off + self.tcb_offset, True)     # ?????

        # at dtv[-1] there's capacity, at dtv[0] there's count (technically generation number?)
        self.drop_int(self.max_modules-1, self.dtv_offset - 2*self.arch.bytes)
        self.drop_int(0, self.dtv_offset)

    def drop(self, string, offset):
        for i, c in enumerate(string):
            self.memory[i + offset] = c

    def drop_int(self, num, offset, needs_relocation=False):
        if needs_relocation:
            self.relocs.append(InternalTLSRelocation(num, offset, self))
            num += self.mapped_base

        self.drop(struct.pack(self.arch.struct_fmt(), num), offset)

    def register_object(self, obj):
        if not obj.tls_used:
            return

        super(ELFTLSObject, self).register_object(obj)

        # tls_block_offset has these semantics: the thread pointer plus the block offset equals the address of the
        # module's TLS data in memory
        if self.arch.elf_tls.variant == 1:
            obj.tls_block_offset = self.total_blocks_size
        else:
            obj.tls_block_offset = -self.total_blocks_size - roundup(obj.tls_block_size)

        self.total_blocks_size += roundup(obj.tls_block_size)
        if self.total_blocks_size > self.max_data:
            raise CLEError("Too much TLS data to handle... file this as a bug")

        # update dtv size
        self.drop_int(len(self.modules), self.dtv_offset)

        # Set up the DTV
        dtv_entry_offset = self.dtv_offset + 2*self.arch.bytes*obj.tls_module_id
        self.drop_int(self.tp_offset + obj.tls_block_offset + self.arch.elf_tls.dtv_entry_offset, dtv_entry_offset, True)
        self.drop_int(1, dtv_entry_offset + self.arch.bytes)

    @property
    def thread_pointer(self):
        """
        The thread pointer. This is a technical term that refers to a specific location in the TLS segment.
        """
        return self.mapped_base + self.tp_offset

    @property
    def user_thread_pointer(self):
        """
        The thread pointer that is exported to the user
        """
        return self.thread_pointer + self.arch.elf_tls.tp_offset

    @property
    def max_addr(self):
        return self.mapped_base + self._max_addr

    def get_addr(self, module_id, offset):
        """
        basically ``__tls_get_addr``.
        """
        return self.user_thread_pointer + self.modules[module_id-1].tls_block_offset + offset
