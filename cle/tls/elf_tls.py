from collections import defaultdict
import struct

TLS_BLOCK_ALIGN = 0x10
TLS_TOTAL_HEAD_SIZE = 0x4000
TLS_HEAD_ALIGN = 0x10000
TLS_DTV_INITIAL_CAPACITY = 0x10
TLS_ALLOC_SIZE = 0x30000


def roundup(val, to=TLS_BLOCK_ALIGN):
    return val - 1 + (to - ((val - 1) % to))

from . import TLSObj


class ELFTLSObj(TLSObj):
    """
    This class is used when parsing the Thread Local Storage of an ELF binary.
    """
    def __init__(self, modules):
        super(ELFTLSObj, self).__init__(modules, filetype='unix')
        module_id = 1
        self.total_blocks_size = 0
        for module in modules:
            module.tls_module_id = module_id
            module_id += 1
            module.tls_block_offset = self.total_blocks_size
            self.total_blocks_size += roundup(module.tls_block_size)

        self.total_blocks_size = roundup(self.total_blocks_size, TLS_HEAD_ALIGN)

        for module in modules:
            if self.arch.elf_tls.variant == 1:
                module.tls_block_offset += TLS_TOTAL_HEAD_SIZE
            else:
                module.tls_block_offset = -roundup(module.tls_block_size) - module.tls_block_offset

        if self.arch.elf_tls.variant == 1:
            self.dtv_offset = TLS_TOTAL_HEAD_SIZE + self.total_blocks_size + 2*self.arch.bytes
            self.tcb_offset = TLS_TOTAL_HEAD_SIZE - self.arch.elf_tls.tcbhead_size
            self.tp_offset = TLS_TOTAL_HEAD_SIZE
        else:
            self.dtv_offset =  TLS_TOTAL_HEAD_SIZE + 2*self.arch.bytes
            self.tcb_offset = self.total_blocks_size
            self.tp_offset = self.total_blocks_size

    def finalize(self):
        assert self.rebase_addr != 0
        temp_dict = defaultdict(lambda: '\0')
        def drop(string, offset):
            for i, c in enumerate(string):
                temp_dict[i + offset] = c
        def drop_int(num, offset):
            drop(struct.pack(self.arch.struct_fmt(), num), offset)

        # Set the appropriate pointers in the tcbhead
        for off in self.arch.elf_tls.head_offsets:
            drop_int(self.thread_pointer, off + self.tcb_offset)
        for off in self.arch.elf_tls.dtv_offsets:
            drop_int(self.rebase_addr + self.dtv_offset, off + self.tcb_offset)
        for off in self.arch.elf_tls.pthread_offsets:
            drop_int(self.thread_pointer, off + self.tcb_offset)     # ?????

        # Write the init images from each of the modules' tdata sections
        for module in self.modules:
            module.memory.seek(module.tls_tdata_start)
            drop(module.memory.read(module.tls_tdata_size), self.tp_offset + module.tls_block_offset)

        # Set up the DTV
        # TODO: lmao capacity it's 2:30am please help me
        drop_int(TLS_DTV_INITIAL_CAPACITY-1, self.dtv_offset - 2*self.arch.bytes)
        drop_int(len(self.modules), self.dtv_offset)
        for module in self.modules:
            drop_int(self.tcb_offset + module.tls_block_offset + self.arch.elf_tls.dtv_entry_offset,
                     self.dtv_offset + (2*self.arch.bytes)*module.tls_module_id)
            drop_int(1,
                     self.dtv_offset + (2*self.arch.bytes)*module.tls_module_id + self.arch.bytes)

        self.memory.add_backer(0, ''.join(temp_dict[i] for i in xrange(0, TLS_ALLOC_SIZE)))


    @property
    def thread_pointer(self):
        return self.rebase_addr + self.tp_offset

    @property
    def user_thread_pointer(self):
        return self.thread_pointer + self.arch.elf_tls.tp_offset

    def get_min_addr(self):
        return self.rebase_addr

    def get_max_addr(self):
        return TLS_ALLOC_SIZE + self.rebase_addr

    def get_addr(self, module_id, offset):
        """
        basically ``__tls_get_addr``.
        """
        return self.user_thread_pointer + self.modules[module_id-1].tls_block_offset + offset
