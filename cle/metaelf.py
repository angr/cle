from .absobj import AbsObj
from .errors import CLEOperationError

__all__ = ('MetaELF',)

class MetaELF(AbsObj):
    """
    A base classt that implements functions used by all backends that can load
    an ELF.
    """
    def __init__(self, *args, **kwargs):
        super(MetaELF, self).__init__(*args, **kwargs)

        self._plt = {}
        self.elfflags = 0
        self.ppc64_initial_rtoc = None

    supported_filetypes = ['elf']

    def _load_plt(self):
        if self.arch.name in ('ARMEL', 'ARMHF', 'ARM', 'AARCH64', 'MIPS32', 'MIPS64'):
            return

        for name in self.jmprel:
            addr = self._get_plt_stub_addr(name)
            self._plt[name] = addr

    def _get_plt_stub_addr(self, name):
        """
        Guess the address of the PLT stub for function @name.
        Functions must have a know GOT entry in self.jmprel

        It should be safe to call regardless of if you've resolved simprocedures
        or not, since those modifications are on the root clemory, and we're manipulating
        one of its backers here.

        NOTE: you probably want to call get_call_stub_addr() instead.
        TODO: sections fallback for statically linked binaries
        """
        if name not in self.jmprel:
            return None

        # What's in the got slot for @name ?
        got = self.jmprel[name].addr
        addr = self.memory.read_addr_at(got)

        # This is the address of the next second instruction in the PLT stub
        # This is hackish but it works

        if self.arch.name in ('X86', 'AMD64'):
            # 0x6 is the size of the plt's jmpq instruction in x86_64
            return addr - 0x6

        elif self.arch.name in ('ARMEL', 'ARMHF', 'ARM', 'AARCH64'):
            return addr

        elif self.arch.name in ('PPC32', 'PPC64'):
            return got

        elif self.arch.name in ('MIPS32', 'MIPS64'):
            return addr

    @property
    def plt(self):
        ''' Maps names to addresses '''
        return {k: v + self.rebase_addr for (k, v) in self._plt.iteritems()}

    @property
    def reverse_plt(self):
        ''' Maps addresses to names '''
        return {v + self.rebase_addr: k for (k, v) in self._plt.iteritems()}

    def get_call_stub_addr(self, name):
        """
        Usually, the PLT stub is called when jumping to an external function.
        """
        # FIXME: this doesn't work on PPC. It will return .plt address of the
        # function, but it is not what is called in practice...
        if self.arch.name in ('ARMEL', 'ARMHF', 'ARM', 'AARCH64', 'PPC32', 'PPC64'):
            raise CLEOperationError("FIXME: this doesn't work on PPC/ARM")

        if name in self._plt:
            return self._plt[name] + self.rebase_addr

    @property
    def is_ppc64_abiv1(self):
        return self.arch.name == 'PPC64' and self.elfflags & 3 < 2

    def _ppc64_abiv1_entry_fix(self):
        """
        On powerpc64, the e_flags elf header entry's lowest two bits determine
        the ABI type. in ABIv1, the entry point given in the elf headers is not
        actually the entry point, but rather the address in memory where there
        exists a pointer to the entry point.

        Utter bollocks, but this function should fix it.
        """

        if self.is_ppc64_abiv1:
            ep_offset = self._entry
            self._entry = self.memory.read_addr_at(ep_offset)
            self.ppc64_initial_rtoc = self.memory.read_addr_at(ep_offset+8)

