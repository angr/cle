import pyvex
import elftools
import os
import logging

from .. import Backend
from ..symbol import SymbolType
from ...address_translator import AT
from ...utils import stream_or_path
from elftools.elf.descriptions import describe_ei_osabi
from collections import OrderedDict

__all__ = ('MetaELF',)

l = logging.getLogger(name=__name__)

def maybedecode(string):
    # so... it turns out that pyelftools is garbage and will transparently give you either strings or bytestrings
    # based on pretty much nothing whatsoever
    return string if type(string) is str else string.decode()

class MetaELF(Backend):
    """
    A base class that implements functions used by all backends that can load an ELF.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        tmp_reader = elftools.elf.elffile.ELFFile(self._binary_stream)
        self.os = describe_ei_osabi(tmp_reader.header.e_ident.EI_OSABI)
        self.elfflags = tmp_reader.header.e_flags
        self._plt = {}
        self._ppc64_abiv1_initial_rtoc = None

    supported_filetypes = ['elf']

    def _block(self, addr, skip_stmts=False):
        # for sanity checking. we live in the world of heuristics now.
        thumb = self.arch.name.startswith("ARM") and addr % 2 == 1
        realaddr = addr
        if thumb: realaddr -= 1
        dat = self.memory.load(AT.from_lva(realaddr, self).to_rva(), 40)
        return pyvex.IRSB(dat, addr, self.arch, bytes_offset=1 if thumb else 0, opt_level=1, skip_stmts=skip_stmts)

    def _add_plt_stub(self, name, addr, sanity_check=True):
        # addr is an LVA
        if addr <= 0: return False
        target_addr = self.jmprel[name].linked_addr
        try:
            if sanity_check and target_addr not in [c.value for c in self._block(addr, skip_stmts=False).all_constants]:
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

        plt_sec = None
        if '.plt' in self.sections_map:
            plt_sec = self.sections_map['.plt']
        if '.plt.got' in self.sections_map:
            plt_sec = self.sections_map['.plt.got']
        if '.MIPS.stubs' in self.sections_map:
            plt_sec = self.sections_map['.MIPS.stubs']

        self.jmprel = OrderedDict(sorted(self.jmprel.items(), key=lambda x: x[1].linked_addr))
        func_jmprel = OrderedDict((k, v) for k, v in self.jmprel.items() if v.symbol.type not in (SymbolType.TYPE_OBJECT, SymbolType.TYPE_SECTION, SymbolType.TYPE_OTHER))

        # ATTEMPT 1: some arches will just leave the plt stub addr in the import symbol
        if self.arch.name in ('ARM', 'ARMEL', 'ARMHF', 'ARMCortexM', 'AARCH64', 'MIPS32', 'MIPS64'):
            for name, reloc in func_jmprel.items():
                if plt_sec is None or plt_sec.contains_addr(reloc.symbol.linked_addr):
                    self._add_plt_stub(name, reloc.symbol.linked_addr, sanity_check=plt_sec is None)

        # ATTEMPT 2: on intel chips the data in the got slot pre-relocation points to a lazy-resolver
        # stub immediately after the plt stub
        if self.arch.name in ('X86', 'AMD64'):
            for name, reloc in func_jmprel.items():
                try:
                    self._add_plt_stub(
                        name,
                        self.memory.unpack_word(reloc.relative_addr) - 6,
                        sanity_check=not self.pic)
                except KeyError:
                    pass

            # do another sanity check
            if len(set(self._plt.values())) != len(self._plt):
                self._plt = {}

        # ATTEMPT 3: one ppc scheme I've seen is that there are 16-byte stubs packed together
        # right before the resolution stubs.
        if self.arch.name in ('PPC32',):
            resolver_stubs = sorted(
                (self.memory.unpack_word(reloc.relative_addr), name)
                for name, reloc in func_jmprel.items()
            )
            if resolver_stubs:
                stubs_table = resolver_stubs[0][0] - 16 * len(resolver_stubs)
                for i, (_, name) in enumerate(resolver_stubs):
                    self._add_plt_stub(name, stubs_table + i*16)

        if len(self._plt) == len(func_jmprel):
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
            if tick.bailout_timer <= 0:
                raise TimeoutError()
        tick.bailout_timer = 5

        def scan_forward(addr, name, push=False):
            names = [name] if type(name) not in (list, tuple) else name
            def block_is_good(blk):
                all_constants = set(c.value for c in blk.all_constants)
                for name in names:
                    gotslot = func_jmprel[name].linked_addr
                    if gotslot in all_constants:
                        block_is_good.name = name
                        return True
                return False
            block_is_good.name = None

            instruction_alignment = self.arch.instruction_alignment
            if self.arch.name in ('ARMEL', 'ARMHF'):
                # hard code alignment for ARM code
                instruction_alignment = 4

            try:
                while True:
                    tick()
                    bb = self._block(addr, skip_stmts=False)

                    step_forward = False
                    # the block shouldn't touch any cc_* registers
                    if self.arch.name in ('X86', 'AMD64', 'ARMEL', 'ARMHF', 'ARMCortexM'):
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

                    if block_is_good(bb):
                        break
                    if bb.jumpkind == 'Ijk_NoDecode':
                        addr += instruction_alignment
                    else:
                        addr += bb.size

                # "push" means try to increase the address as far as we can without regard for semantics
                # the alternative is to only try to lop off nop instructions
                if push:
                    if block_is_good.name is None:
                        raise ValueError('block_is_good.name cannot be None.')
                    old_name = block_is_good.name
                    block = self._block(addr, skip_stmts=True)
                    if len(block.instruction_addresses) > 1:
                        for instruction in block.instruction_addresses[1:]:
                            candidate_block = self._block(instruction, skip_stmts=False)
                            if block_is_good(candidate_block) and block_is_good.name == old_name:
                                addr = candidate_block.addr
                            else:
                                break
                    block_is_good.name = old_name
                else:
                    cont = True
                    while cont:
                        cont = False
                        seen_imark = False
                        # we need to access bb.statements
                        if bb.statements is None:
                            # relift without skipping statements
                            bb = self._block(bb.addr, skip_stmts=False)
                        for stmt in bb.statements:
                            if stmt.tag == 'Ist_IMark':
                                if seen_imark:
                                    # good????
                                    bb = self._block(stmt.addr, skip_stmts=False)
                                    if block_is_good(bb):
                                        addr = stmt.addr
                                        cont = True
                                    break
                                else:
                                    seen_imark = True
                            elif stmt.tag == 'Ist_Put' and stmt.offset == bb.offsIP:
                                continue
                            else:
                                # there's some behavior, not good
                                break
                return self._add_plt_stub(block_is_good.name, addr)
            except (TimeoutError, ValueError, KeyError, pyvex.PyVEXError):
                return False

        if not self._plt and '__libc_start_main' in func_jmprel and self.entry != 0:
            # try to scan forward through control flow to find __libc_start_main!
            try:
                last_jk = None
                addr = self.entry
                bb = self._block(addr, skip_stmts=True)
                target = bb.default_exit_target
                while target is not None:
                    tick()
                    last_jk = bb.jumpkind
                    addr = target
                    bb = self._block(addr, skip_stmts=True)
                    target = bb.default_exit_target

                if last_jk == 'Ijk_Call':
                    self._add_plt_stub('__libc_start_main', addr)
            except (TimeoutError, KeyError, pyvex.PyVEXError):
                pass

        # if func_jmprel.keys()[0] not in self._plt:
        if not set(func_jmprel.keys()).intersection(self._plt.keys()):
            # Check if we have a .plt section
            if plt_sec is None:
                # WAHP WAHP
                return

        if plt_sec is not None:
            # LAST TRY: Find the first block to references ANY GOT slot
            tick.bailout_timer = 5
            scan_forward(plt_sec.vaddr, list(func_jmprel.keys()), push=True)

        if not self._plt:
            # \(_^^)/
            return

        # if we've gotten this far there is at least one plt slot address known, guaranteed.
        plt_hitlist = [
                (name, AT.from_rva(self._plt[name], self).to_lva() if name in self._plt else None)
                for name in func_jmprel
            ]

        name, addr = plt_hitlist[0]
        if addr is None and plt_sec is not None:
            # try to resolve the very first entry
            tick.bailout_timer = 5
            guessed_addr = plt_sec.vaddr
            scan_forward(guessed_addr, name)
            if name in self._plt:
                # resolved :-)
                plt_hitlist[0] = (name, AT.from_rva(self._plt[name], self).to_lva())

        next_addr = None
        for i, (name, addr) in enumerate(plt_hitlist):
            if addr is None:
                if next_addr is None:
                    continue
                tick.bailout_timer = 5
                scan_forward(next_addr, name)
                if name in self._plt:
                    addr = AT.from_rva(self._plt[name], self).to_lva()

            if addr is not None:
                b0 = self._block(addr, skip_stmts=True)
                stub_size = b0.size
                if isinstance(b0.next, pyvex.expr.Const) and b0.next.con.value == addr + b0.size:
                    b1 = self._block(addr + b0.size, skip_stmts=True)
                    stub_size += b1.size
                next_addr = addr + stub_size

    @property
    def plt(self):
        """
        Maps names to addresses.
        """
        return {k: AT.from_rva(self._plt[k], self).to_mva() for k in self._plt}

    @property
    def reverse_plt(self):
        """
        Maps addresses to names.
        """
        return {AT.from_rva(self._plt[k], self).to_mva(): k for k in self._plt}

    @property
    def is_ppc64_abiv1(self):
        """
        Returns whether the arch is PowerPC64 ABIv1.

        :return: True if PowerPC64 ABIv1, False otherwise.
        """
        return self.arch.name == 'PPC64' and self.elfflags & 3 < 2

    @property
    def is_ppc64_abiv2(self):
        """
        Returns whether the arch is PowerPC64 ABIv2.

        :return: True if PowerPC64 ABIv2, False otherwise.
        """
        return self.arch.name == 'PPC64' and self.elfflags & 3 == 2

    @property
    def ppc64_initial_rtoc(self):
        """
        Get initial rtoc value for PowerPC64 architecture.
        """
        if self.is_ppc64_abiv1:
            return self._ppc64_abiv1_initial_rtoc
        elif self.is_ppc64_abiv2:
            return self._ppc64_abiv2_get_initial_rtoc()
        else:
            return None

    def _ppc64_abiv1_entry_fix(self):
        """
        On PowerPC64, the e_flags elf header entry's lowest two bits determine the ABI type. in ABIv1, the entry point
        given in the elf headers is not actually the entry point, but rather the address in memory where there
        exists a pointer to the entry point.

        Utter bollocks, but this function should fix it.
        """
        if self.is_ppc64_abiv1:
            ep_offset = self._entry
            self._entry = self.memory.unpack_word(AT.from_lva(ep_offset, self).to_rva())
            self._ppc64_abiv1_initial_rtoc = self.memory.unpack_word(AT.from_lva(ep_offset+8, self).to_rva())

    def _ppc64_abiv2_get_initial_rtoc(self):
        """
        Guess initial table of contents value for PPC64 based on .got section.

        According to PPC64 ABIv2 Specification (Section 3.3): "the TOC pointer
        register typically points to the beginning of the .got section +
        0x8000." Guess the initial rtoc value based on that to handle the
        typical case.
        """
        got_section = self.sections_map.get('.got', None)
        if got_section is None:
            l.warning('Failed to guess initial rtoc value due to missing .got')
            return None
        return got_section.vaddr + 0x8000

    @staticmethod
    def extract_soname(path):
        with stream_or_path(path) as f:
            try:
                e = elftools.elf.elffile.ELFFile(f)
                for seg in e.iter_segments():
                    if seg.header.p_type == 'PT_NULL':
                        break
                    elif seg.header.p_type == 'PT_DYNAMIC':
                        for tag in seg.iter_tags():
                            if tag.entry.d_tag == 'DT_SONAME':
                                return maybedecode(tag.soname)
                        if type(path) is str:
                            return os.path.basename(path)

            except elftools.common.exceptions.ELFError:
                pass
            return None

    @staticmethod
    def get_text_offset(path):
        """
        Offset of .text in the binary.
        """
        with stream_or_path(path) as f:
            e = elftools.elf.elffile.ELFFile(f)
            return e.get_section_by_name(".text").header.sh_offset
