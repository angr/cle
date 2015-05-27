from .absobj import AbsObj
from .errors import CLEOperationError

__all__ = ('MetaELF',)

class MetaELF(AbsObj):
    """
    A metaclass that implements functions used by all backends that can load
    an ELF.
    """
    def __init__(self, *args, **kwargs):
        super(MetaELF, self).__init__(*args, **kwargs)

        self.plt = {}
        self.elfflags = 0

    supported_filetypes = ['elf']

    def _load_plt(self):
        if self.arch.name in ('ARMEL', 'ARMHF', 'MIPS32'):
            return

        for name in self.jmprel:
            #FIXME: shouldn't we use get_call_stub_addr(name) instead ??
            addr = self._get_plt_stub_addr(name)
            self.plt[name] = addr

    def _get_plt_stub_addr(self, name):
        """
        Guess the address of the PLT stub for function @name.
        Functions must have a know GOT entry in self.jmprel

        NOTE: you probably want to call get_call_stub_addr() instead.
        TODO: sections fallback for statically linked binaries
        WARNING: call this after loading the binary image, but *before* resolving
        SimProcedures.
        """
        if name not in self.jmprel.keys():
            return None

        # What's in the got slot for @name ?
        got = self.jmprel[name].addr
        addr = self.memory.read_addr_at(got)

        # This is the address of the next second instruction in the PLT stub
        # This is hackish but it works

        if self.arch.name in ('X86', 'AMD64'):
            # 0x6 is the size of the plt's jmpq instruction in x86_64
            return addr - 0x6

        elif self.arch.name in ('ARMEL', 'ARMHF'):
            return addr

        elif self.arch.name in ('PPC32', 'PPC64'):
            return got

        elif self.arch.name == 'MIPS32':
            return addr

    def get_call_stub_addr(self, name):
        """
        Usually, the PLT stub is called when jumping to an external function.
        """
        # FIXME: this doesn't work on PPC. It will return .plt address of the
        # function, but it is not what is called in practice...
        if self.arch.name in ('ARMEL', 'ARMHF', 'PPC32', 'PPC64'):
            raise CLEOperationError("FIXME: this doesn't work on PPC/ARM")

        if name in self.plt.keys():
            return self.plt[name]

    def _ppc64_abiv1_entry_fix(self):
        """
        On powerpc64, the e_flags elf header entry's lowest two bits determine
        the ABI type. in ABIv1, the entry point given in the elf headers is not
        actually the entry point, but rather the address in memory where there
        exists a pointer to the entry point.

        Utter bollocks, but this function should fix it.
        """

        if self.arch.name != 'PPC64': return
        if self.elfflags & 3 < 2:
            ep_offset = self._entry
            self._entry = self.memory.read_addr_at(ep_offset)
            self.ppc64_initial_rtoc = self.memory.read_addr_at(ep_offset+8)

