import pyvex
import elftools
import os

from .. import Backend
from ...address_translator import AT
from ...utils import stream_or_path
from elftools.elf.descriptions import describe_ei_osabi

__all__ = ('MetaELF',)

class MetaELF(Backend):
    """
    A base class that implements functions used by all backends that can load an ELF.
    """
    def __init__(self, *args, **kwargs):
        super(MetaELF, self).__init__(*args, **kwargs)
        self.os = describe_ei_osabi(elftools.elf.elffile.ELFFile(self.binary_stream).header.e_ident.EI_OSABI)
        self._plt = {}
        self.elfflags = 0
        self.ppc64_initial_rtoc = None

    supported_filetypes = ['elf']

    def _block(self, addr):
        # for sanity checking. we live in the world of heuristics now.
        thumb = self.arch.name.startswith("ARM") and addr % 2 == 1
        realaddr = addr
        if thumb: realaddr -= 1
        dat = ''.join(self.memory.read_bytes(AT.from_lva(realaddr, self).to_rva(), 40))
        return pyvex.IRSB(dat, addr, self.arch, bytes_offset=1 if thumb else 0, opt_level=1)

    def _add_plt_stub(self, name, addr, sanity_check=True):
        # addr is an LVA
        if addr == 0: return False
        target_addr = self.jmprel[name].linked_addr
        try:
            if sanity_check and target_addr not in [c.value for c in self._block(addr).all_constants]:
                return False
        except (pyvex.PyVEXError, KeyError):
            return False
        else:
            self._plt[name] = AT.from_lva(addr, self).to_rva()
            return True

    def _load_plt(self):
        # The main problem here is that there's literally no good way to do this.
        # like, I read through the binutils source and they have a hacked up solution for each arch
        # that performs actual comparisons against the machine code in the plt section.
        # it's pretty bad.
        # we sanity-check all our attempts by requiring that the block lifted at the given address
        # references the GOT slot for the symbol.

        # ATTEMPT 1: some arches will just leave the plt stub addr in the import symbol
        if self.arch.name in ('ARM', 'ARMEL', 'ARMHF', 'AARCH64', 'MIPS32', 'MIPS64'):
            plt_sec = None
            if '.plt' in self.sections_map:
                plt_sec = self.sections_map['.plt']
            if '.MIPS.stubs' in self.sections_map:
                plt_sec = self.sections_map['.MIPS.stubs']

            for name, reloc in self.jmprel.iteritems():
                if plt_sec is None or plt_sec.contains_addr(reloc.symbol.linked_addr):
                    self._add_plt_stub(name, reloc.symbol.linked_addr, sanity_check=plt_sec is None)

        # ATTEMPT 2: on intel chips the data in the got slot pre-relocation points to a lazy-resolver
        # stub immediately after the plt stub
        if self.arch.name in ('X86', 'AMD64'):
            for name, reloc in self.jmprel.iteritems():
                try:
                    self._add_plt_stub(
                        name,
                        self.memory.read_addr_at(reloc.relative_addr) - 6,
                        sanity_check=not self.pic)
                except KeyError:
                    pass

            # do another sanity check
            if len(set(self._plt.itervalues())) != len(self._plt):
                self._plt = {}

        # ATTEMPT 3: one ppc scheme I've seen is that there are 16-byte stubs packed together
        # right before the resolution stubs.
        if self.arch.name in ('PPC32',):
            resolver_stubs = sorted(
                (self.memory.read_addr_at(reloc.relative_addr), name)
                for name, reloc in self.jmprel.iteritems()
            )
            if resolver_stubs:
                stubs_table = resolver_stubs[0][0] - 16 * len(resolver_stubs)
                for i, (_, name) in enumerate(resolver_stubs):
                    self._add_plt_stub(name, stubs_table + i*16)

        if len(self._plt) == len(self.jmprel):
            # real quick, bail out before shit hits the fan
            return

        # ATTEMPT 4:
        # ok. time to go in on this.
        # try to find a single plt stub, anywhere. if we already have one, use that, otherwise
        # try to scan forward from _start to __libc_start_main to find that one.
        # then, scan forward and backward from that stub to find the rest of them. yikes!

        # keep a timer so we don't get stuck. keep this short and sweet.
        def tick():
            tick.bailout_timer -= 1
            assert tick.bailout_timer > 0
        tick.bailout_timer = 5

        def scan_forward(addr, name, push=False):
            gotslot = self.jmprel[name].linked_addr

            instruction_alignment = self.arch.instruction_alignment
            if self.arch.name in ('ARMEL', 'ARMHF'):
                # hard code alignment for ARM code
                instruction_alignment = 4

            try:
                while True:
                    tick()
                    bb = self._block(addr)

                    step_forward = False
                    # the block shouldn't touch any cc_* registers
                    if self.arch.name in ('X86', 'AMD64', 'ARMEL', 'ARMHF'):
                        cc_regs = { self.arch.registers['cc_op'][0], self.arch.registers['cc_ndep'][0],
                                    self.arch.registers['cc_dep1'][0], self.arch.registers['cc_dep2'][0]
                                    }
                        if any([ isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset in cc_regs
                                 for stmt in bb.statements ]):
                            step_forward = True
                        elif any( [ isinstance(stmt, pyvex.IRStmt.WrTmp) and isinstance(stmt.data, pyvex.IRExpr.Get)
                                    and stmt.data.offset in cc_regs for stmt in bb.statements ]):
                            step_forward = True

                    if step_forward:
                        # only steps one instruction forward
                        addr += instruction_alignment
                        continue

                    if gotslot in [c.value for c in bb.all_constants]:
                        break
                    if bb.jumpkind == 'Ijk_NoDecode':
                        addr += instruction_alignment
                    else:
                        addr += bb.size

                while push and gotslot in [c.value for c in self._block(addr + instruction_alignment).all_constants]:
                    addr += instruction_alignment
                return self._add_plt_stub(name, addr)
            except (AssertionError, KeyError, pyvex.PyVEXError):
                return False

        if not self._plt and '__libc_start_main' in self.jmprel and self.entry != 0:
            # try to scan forward through control flow to find __libc_start_main!
            try:
                last_jk = None
                addr = self.entry
                bb = self._block(addr)
                target = bb._get_defaultexit_target()
                while target is not None:
                    tick()
                    last_jk = bb.jumpkind
                    addr = target
                    bb = self._block(addr)
                    target = bb._get_defaultexit_target()

                if last_jk == 'Ijk_Call':
                    self._add_plt_stub('__libc_start_main', addr)
            except (AssertionError, KeyError, pyvex.PyVEXError):
                pass

        # if self.jmprel.keys()[0] not in self._plt:
        if not set(self.jmprel.keys()).intersection(self._plt.keys()):
            # LAST TRY: check if we have a .plt section
            if '.plt' not in self.sections_map:
                # WAHP WAHP
                return

            # try to find a block that references the first GOT slot
            tick.bailout_timer = 5
            scan_forward(self.sections_map['.plt'].vaddr, self.jmprel.keys()[0], push=True)

        if not self._plt:
            # \(_^^)/
            return

        # if we've gotten this far there is at least one plt slot address known, guaranteed.
        plt_hitlist = [
                (name, AT.from_rva(self._plt[name], self).to_lva() if name in self._plt else None)
                for name in self.jmprel
            ]
        last_good_idx = None
        stub_size = None

        name, addr = plt_hitlist[0]
        if addr is None:
            # try to resolve the very first entry
            tick.bailout_timer = 5
            guessed_addr = plt_sec.vaddr
            scan_forward(guessed_addr, name)
            if name in self._plt:
                # resolved :-)
                plt_hitlist[0] = (name, AT.from_rva(self._plt[name], self).to_lva())

        for i, (name, addr) in enumerate(plt_hitlist):
            if addr is not None:
                last_good_idx = i
                if stub_size is None:
                    b0 = self._block(addr)
                    stub_size = b0.size
                    if isinstance(b0.next, pyvex.expr.Const) and b0.next.con.value == addr + b0.size:
                        b1 = self._block(addr + b0.size)
                        stub_size += b1.size
                continue

            if last_good_idx is None:
                continue

            tick.bailout_timer = 5
            guess_addr = plt_hitlist[last_good_idx][1] + (i - last_good_idx) * stub_size
            scan_forward(guess_addr, name)


    @property
    def plt(self):
        """
        Maps names to addresses.
        """
        return {k: AT.from_rva(v, self).to_mva() for (k, v) in self._plt.iteritems()}

    @property
    def reverse_plt(self):
        """
        Maps addresses to names.
        """
        return {AT.from_rva(v, self).to_mva(): k for (k, v) in self._plt.iteritems()}

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
            self._entry = self.memory.read_addr_at(AT.from_lva(ep_offset, self).to_rva())
            self.ppc64_initial_rtoc = self.memory.read_addr_at(AT.from_lva(ep_offset+8, self).to_rva())

    @staticmethod
    def extract_soname(path):
        with stream_or_path(path) as f:
            try:
                e = elftools.elf.elffile.ELFFile(f)
                # TODO: make this not depend on sections...
                dyn = e.get_section_by_name('.dynamic')
                if dyn is None:
                    return None

                soname = [ x.soname for x in list(dyn.iter_tags()) if x.entry.d_tag == 'DT_SONAME']
                if not soname:
                    if type(path) in (str, unicode):
                        return os.path.basename(path)
                    return None
                return soname[0]
            except elftools.common.exceptions.ELFError:
                return None

    @staticmethod
    def get_text_offset(path):
        """
        Offset of .text in the binary.
        """
        with stream_or_path(path) as f:
            e = elftools.elf.elffile.ELFFile(f)
            return e.get_section_by_name(".text").header.sh_offset
