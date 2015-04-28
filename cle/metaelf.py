from .abs_obj import AbsObj
from .clexception import CLException

class MetaELF(AbsObj):
    def __init__(self, *args, **kwargs):
        super(MetaELF, self).__init__(*args, **kwargs)
        self.plt = {}
        self.elfflags = 0

    def _load_plt(self):
        if "arm" in self.archinfo.name or 'mips' in self.archinfo.name:
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
            #raise CLException("%s does not figure in the GOT")

        # What's in the got slot for @name ?
        got = self.jmprel[name].addr
        addr = self.memory.read_addr_at(got)

        # This is the address of the next second instruction in the PLT stub
        # This is hackish but it works

        if self.archinfo.name in ["i386:x86-64", "i386"]:
            # 0x6 is the size of the plt's jmpq instruction in x86_64
            return addr - 0x6

        elif "arm" in self.archinfo.name:
            return addr

        elif "powerpc" in self.archinfo.name:
            return got

        elif "mips" in self.archinfo.name:
            return addr

    def get_call_stub_addr(self, name):
        """
        Usually, the PLT stub is called when jumping to an external function.
        """
        # FIXME: this doesn't work on PPC. It will return .plt address of the
        # function, but it is not what is called in practice...
        if "powerpc" in self.archinfo.name or "arm" in self.archinfo.name:
            raise CLException("FXIME: this doesn't work on PPC/ARM")

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

        if self.archinfo.qemu_arch != 'ppc64': return
        if self.elfflags & 3 < 2:
            ep_offset = self.entry
            self.entry = self.memory.read_addr_at(ep_offset)
            self.ppc64_initial_rtoc = self.memory.read_addr_at(ep_offset+8)

