from ..backends import Backend
from ..errors import CLEOperationError

__all__ = ('MetaELF',)

class MetaELF(Backend):
    """
    A base class that implements functions used by all backends that can load an ELF.
    """
    def __init__(self, *args, **kwargs):
        super(MetaELF, self).__init__(*args, **kwargs)

        self._plt = {}
        self.elfflags = 0
        self.ppc64_initial_rtoc = None

    supported_filetypes = ['elf']

    def _load_plt(self):
        # The main problem here is that there's literally no good way to do this.
        # like, I read through the binutils source and they have a hacked up solution for each arch.
        # it's pretty bad.

        if self.arch.name in ('X86', 'AMD64'):
            # this is not the solution that binutils uses
            # binutils actually just assumes that there exists a header of
            # lazy-resolver-code at the top of .plt, and then for each
            # n bytes after that, there's a plt stub
            # The way we're doing it is assuming that the lazy-resolver stub lives
            # immediately after the plt stub, which is a single jump instruction.
            for name, reloc in self.jmprel.iteritems():
                self._plt[name] = self.memory.read_addr_at(reloc.addr) - 6

        elif self.arch.name in ('ARM', 'ARMEL', 'ARMHF', 'AARCH64', 'MIPS32', 'MIPS64'):
            # ARM and MIPS are nice enough to store the PLT stub addr in the
            # import symbol itself. Sweet!
            for name, reloc in self.jmprel.iteritems():
                self._plt[name] = reloc.symbol.addr

        elif self.arch.name in ('PPC32',):
            # Yikes, ok. so for this one we just gotta assume that there are 16-byte
            # stubs packed together right before the resolution stubs??????????
            # binutils does some terrifying stuff with actually looking at the
            # bytes of the instructions in parts of the text section
            resolver_stubs = sorted((self.memory.read_addr_at(reloc.addr), name) for name, reloc in self.jmprel.iteritems())
            stubs_table = resolver_stubs[0][0] - 16 * len(resolver_stubs)
            for i, (_, name) in enumerate(resolver_stubs):
                self._plt[name] = stubs_table + i*16

        elif self.arch.name in ('PPC64',):
            # ??????????????????????????
            # ????????????????????????????????????????????????
            # confused sobbing noises????????????
            pass

    @property
    def plt(self):
        """
        Maps names to addresses.
        """
        return {k: v + self.rebase_addr for (k, v) in self._plt.iteritems()}

    @property
    def reverse_plt(self):
        """
        Maps addresses to names.
        """
        return {v + self.rebase_addr: k for (k, v) in self._plt.iteritems()}

    def get_call_stub_addr(self, name):
        """
        Takes the name of an imported function and returns the address of the stub function that jumps to it.
        """
        if self.arch.name in ('PPC64',):
            raise CLEOperationError("FIXME: this doesn't work on PPC64")

        if name in self._plt:
            return self._plt[name] + self.rebase_addr
        return None

    @property
    def is_ppc64_abiv1(self):
        """
        Returns whether the arch is powerpc64 ABIv1.

        :return: True if powerpc64 ABIv1, False otherwise.
        """
        return self.arch.name == 'PPC64' and self.elfflags & 3 < 2

    def _ppc64_abiv1_entry_fix(self):
        """
        On powerpc64, the e_flags elf header entry's lowest two bits determine the ABI type. in ABIv1, the entry point
        given in the elf headers is not actually the entry point, but rather the address in memory where there
        exists a pointer to the entry point.

        Utter bollocks, but this function should fix it.
        """

        if self.is_ppc64_abiv1:
            ep_offset = self._entry
            self._entry = self.memory.read_addr_at(ep_offset)
            self.ppc64_initial_rtoc = self.memory.read_addr_at(ep_offset+8)

