import os
import struct
import elftools
import logging
from collections import defaultdict

from .elf import ELF
from ..blob import Blob
from .. import register_backend
from ...errors import CLEError, CLECompatibilityError
from ...memory import Clemory
from ...address_translator import AT

l = logging.getLogger(name=__name__)

# TODO: yall know struct.unpack_from exists, right? maybe even bitstream?


class ELFCore(ELF):
    """
    Loader class for ELF core files.
    """
    is_default = True # Tell CLE to automatically consider using the ELFCore backend

    def __init__(self, *args, executable=None, **kwargs):
        super().__init__(*args, **kwargs)

        self.filename_lookup = []
        self.__current_thread = None
        self._threads = []
        self.auxv = {}
        self._main_filepath = executable

        self.__extract_note_info()

        self.__reload_children()

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith(b'\x7fELF'):
            if elftools.elf.elffile.ELFFile(stream).header['e_type'] == 'ET_CORE':
                return True
            return False
        return False

    def __cycle_thread(self):
        if self.__current_thread is not None:
            self._threads.append(self.__current_thread)
        self.__current_thread = {}

    @property
    def threads(self):
        return list(range(len(self._threads)))

    def thread_registers(self, thread=None):
        if thread is None:
            thread = 0
        return self._threads[thread]['registers']

    def __extract_note_info(self):
        """
        All meaningful information about the process's state at crashtime is stored in the note segment.
        """
        for seg_readelf in self._reader.iter_segments():
            if seg_readelf.header.p_type == 'PT_NOTE':
                for note in seg_readelf.iter_notes():
                    if note.n_type == 'NT_PRSTATUS':
                        self.__cycle_thread()
                        self.__parse_prstatus(note.n_desc.encode('latin-1'))  # ???
                    elif note.n_type == 'NT_FILE':
                        self.__parse_files(note.n_desc)
                    elif note.n_type == 'NT_AUXV':
                        self.__parse_auxv(note.n_desc.encode('latin-1'))
                    elif note.n_type == 512 and self.arch.name == 'X86':
                        self.__parse_x86_tls(note.n_desc.encode('latin-1'))

        self.__cycle_thread()
        if not self._threads:
            l.warning("Could not find thread info, cannot initialize registers")
        elif self.arch.name == 'X86' and 'segments' not in self._threads[0]:
            if 'AT_RANDOM' in self.auxv:
                l.warning("This core dump does not contain TLS information. threads will be matched to TLS regions via heuristics")
                pointer_rand = self.auxv['AT_RANDOM'][4:8]
                all_locations = [addr - 0x18 for addr in self.__dummy_clemory.find(pointer_rand) if self.__dummy_clemory.unpack_word(addr - 0x18) == addr - 0x18]
                # the heuristic is that generally threads are allocated with descending tls addresses
                for thread, loc in zip(self._threads, reversed(all_locations)):
                    thread['segments'] = {thread['registers']['gs'] >> 3: (loc, 0xfffff, 0x51)}
            else:
                l.warning("This core dump does not contain TLS or auxv information. TLS information will be wrong.")
                for thread in self._threads:
                    thread['segments'] = {thread['registers']['gs'] >> 3: (0, 0xffffffff, 0x51)}

    @property
    def __dummy_clemory(self):
        dummy_clemory = Clemory(self.arch, root=True)
        dummy_clemory.add_backer(self.linked_base, self.memory)
        return dummy_clemory


    def __parse_prstatus(self, desc):
        """
        Parse out the prstatus, accumulating the general purpose register values. Supports AMD64, X86, ARM, and AARCH64
        at the moment.

        :param prstatus: a note object of type NT_PRSTATUS.
        """

        # TODO: support all architectures angr supports

        result = {}
        result['si_signo'], result['si_code'], result['si_errno'] = struct.unpack("<3I", desc[:12])

        # this field is a short, but it's padded to an int
        result['pr_cursig'] = struct.unpack("<I", desc[12:16])[0]

        arch_bytes = self.arch.bytes
        if arch_bytes == 4:
            fmt = "I"
        elif arch_bytes == 8:
            fmt = "Q"
        else:
            raise CLEError("Architecture must have a bitwidth of either 64 or 32")

        result['pr_sigpend'], result['pr_sighold'] = struct.unpack("<" + (fmt * 2), desc[16:16+(2*arch_bytes)])

        attrs = struct.unpack("<IIII", desc[16+(2*arch_bytes):16+(2*arch_bytes)+(4*4)])
        result['pr_pid'], result['pr_ppid'], result['pr_pgrp'], result['pr_sid'] = attrs

        # parse out the 4 timevals
        pos = 16+(2*arch_bytes)+(4*4)
        usec = struct.unpack("<" + fmt, desc[pos:pos+arch_bytes])[0] * 1000
        result['pr_utime_usec'] = struct.unpack("<" + fmt, desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, desc[pos:pos+arch_bytes])[0] * 1000
        result['pr_stime_usec'] = struct.unpack("<" + fmt, desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, desc[pos:pos+arch_bytes])[0] * 1000
        result['pr_cutime_usec'] = struct.unpack("<" + fmt, desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, desc[pos:pos+arch_bytes])[0] * 1000
        result['pr_cstime_usec'] = struct.unpack("<" + fmt, desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2

        # parse out general purpose registers
        if self.arch.name == 'AMD64':
            # register names as they appear in dump
            rnames = ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx',
                    'rdx', 'rsi', 'rdi', 'xxx', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'fs_base', 'gs_base', 'ds', 'es',
                    'xxx', 'xxx']
            nreg = 27
        elif self.arch.name == 'X86':
            rnames = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs', 'gs', 'xxx', 'eip',
                    'cs', 'eflags', 'esp', 'ss']
            nreg = 17
        elif self.arch.name == 'ARMHF' or self.arch.name == 'ARMEL':
            rnames = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
                    'r14', 'r15', 'xxx', 'xxx']
            nreg = 18
        elif self.arch.name == 'AARCH64':
            rnames =  ['x%d' % i for i in range(32)]
            rnames.append('pc')
            rnames.append('xxx')
            nreg = 34
        elif self.arch.name == 'MIPS32':
            rnames = ['xxx', 'xxx', 'xxx', 'xxx', 'xxx', 'xxx',
                    'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
                    't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                    's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                    't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra',
                    'lo', 'hi', 'pc', 'bad', 'sr', 'status', 'cause']
            nreg = 45
        else:
            raise CLECompatibilityError("Architecture '%s' unsupported by ELFCore" % self.arch.name)

        regvals = []
        for idx in range(pos, pos+nreg*arch_bytes, arch_bytes):
            regvals.append(struct.unpack("<" + fmt, desc[idx:idx+arch_bytes])[0])
        result['registers'] = dict(zip(rnames, regvals))
        del result['registers']['xxx']

        pos += nreg * arch_bytes
        result['pr_fpvalid'] = struct.unpack("<I", desc[pos:pos+4])[0]
        self.__current_thread.update(result)

    def __parse_files(self, desc):
        self.filename_lookup = [(ent.vm_start, ent.vm_end, ent.page_offset * desc.page_size, fn.decode()) for ent, fn in zip(desc.Elf_Nt_File_Entry, desc.filename)]

        # TODO this can be less stupid if we just parse out what the name/address of the main executable is
        # that metadata has to be somewhere, right?
        matched = None
        if self.filename_lookup and self._main_filepath is not None:
            for i, (a, b, c, fn) in enumerate(self.filename_lookup):
                if os.path.basename(self._main_filepath) == fn[fn.rfind('/')+1:]: # explicit unix basename
                    matched = fn
                    break
            else:
                matched = self.filename_lookup[0][-1]

        for i, (a, b, c, fn) in enumerate(self.filename_lookup):
            if fn == matched:
                self.filename_lookup[i] = (a, b, c, self._main_filepath)


    def __parse_x86_tls(self, desc):
        self.__current_thread['segments'] = {}
        for offset in range(0, len(desc), 4*4):
            index, base, limit, flags = struct.unpack_from('4I', desc, offset)
            self.__current_thread['segments'][index] = (base, limit, flags)

    def __parse_auxv(self, desc):
        for offset in range(0, len(desc), self.arch.bytes*2):
            code = struct.unpack_from(self.arch.struct_fmt(), desc, offset)[0]
            value = struct.unpack_from(self.arch.struct_fmt(), desc, offset + self.arch.bytes)[0]
            code_str = auxv_codes.get(code, code)

            if code_str == 'AT_RANDOM':
                value = self.__dummy_clemory.load(value, 0x10)
            elif code_str in ('AT_EXECFN', 'AT_PLATFORM'):
                pos = value
                value = bytearray()
                while True:
                    byte = self.__dummy_clemory[pos]
                    if byte == 0:
                        break
                    value.append(byte)
                    pos += 1
                value = bytes(value)

            self.auxv[code_str] = value

    def __reload_children(self):
        # god damn. hacks start here
        self.loader.page_size = 0x1000
        self.loader._perform_relocations = False

        # hack: we are using a loader internal method in a non-kosher way which will cause our children to be
        # marked as the main binary if we are also the main binary
        # work around this by setting ourself here:
        if self.loader.main_object is None:
            self.loader.main_object = self

        child_patches = defaultdict(list)
        for vm_start, vm_end, offset, filename in self.filename_lookup:
            try:
                patch_data = self.__dummy_clemory.load(vm_start, vm_end-vm_start)
            except KeyError:
                pass
            else:
                child_patches[filename].append((vm_start, offset, patch_data))

        remaining_segments = list(self.segments)

        for filename, patches in child_patches.items():
            try:
                with open(filename, 'rb') as fp:
                    obj = self.loader._load_object_isolated(fp)
            except FileNotFoundError:
                l.warning("Could not load %s; core may be incomplete", filename)
                if self.loader.main_object is self:
                    self.loader.main_object = None
                self.child_objects.clear()
                return

            # several ways to try to match the NT_FILE entries to the object
            # (not trivial because offsets can be mapped multiple places)
            # (and because there's no clear pattern for how mappings are included or omitted)
            base_addr = None

            # try one: use the delta between each allocation as a signature (works when the text segment is missing)
            if base_addr is None:
                vm_starts = [a for a, _, _ in patches]
                vm_deltas = [b - a for a, b in zip(vm_starts, vm_starts[1:])]
                segment_starts = [seg.vaddr for seg in obj.segments]
                segment_deltas = [b - a for a, b in zip(segment_starts, segment_starts[1:])]

                # funky lil algorithm to find substrings
                for match_idx in range(len(segment_deltas) - len(vm_deltas) + 1):
                    for idx, vm_delta in enumerate(vm_deltas):
                        if vm_delta != segment_deltas[match_idx + idx]:
                            break
                    else:
                        base_addr = vm_starts[0] - AT.from_lva(obj.segments[match_idx].vaddr, obj).to_rva()
                        break

            # try two: if the file is identity-mapped, it's easy (?)
            if base_addr is None:
                base_reccomendations = [a - b for a, b, _ in patches]
                if all(a == base_reccomendations[0] for a in base_reccomendations):
                    base_addr = base_reccomendations[0]

            # try three: if we have the zero offset then it's easy (?)
            if base_addr is None:
                if patches[0][1] == 0:
                    base_addr = patches[0][0]

            if base_addr is None:
                l.warning("Could not load %s (could not determine base); core may be incomplete", filename)
                if self.loader.main_object is self:
                    self.loader.main_object = None
                self.child_objects.clear()
                return

            # store data provided by core into object
            for vaddr, _, patch in patches:
                try:
                    obj.memory.store(vaddr - base_addr, patch)
                except KeyError:
                    pass  # this case handled below in the inject clause, right???

            obj._custom_base_addr = base_addr
            self.child_objects.append(obj)

            # remove any core segments which are handled by this object
            for seg in obj.segments:
                addr = AT.from_lva(seg.vaddr, obj).to_rva() + base_addr
                for subaddr in range(addr, addr + seg.memsize, 0x1000):
                    match_seg = self.find_segment_containing(subaddr)
                    if match_seg is not None:
                        try:
                            remaining_segments.remove(match_seg)
                        except ValueError:
                            pass

            # inject any core segments which are not handled by the object but overlap with it
            max_addr = base_addr + (obj.max_addr - obj.min_addr)
            i = 0
            while i < len(remaining_segments):
                seg = remaining_segments[i]
                if base_addr <= seg.vaddr <= max_addr or seg.vaddr <= base_addr < seg.vaddr + seg.memsize:
                    remaining_segments.pop(i)

                    seg_vaddr, backer = next(self.memory.backers(AT.from_mva(seg.vaddr, self).to_rva()))
                    assert seg_vaddr == AT.from_mva(seg.vaddr, self).to_rva()
                    obj.memory.add_backer(seg.vaddr - base_addr, backer)
                else:
                    i += 1

        # for all remaining segments, make blobs out of them
        mem = self.__dummy_clemory
        for seg in remaining_segments:
            obj = Blob(self.binary, mem, segments=[(seg.vaddr, seg.vaddr, seg.memsize)], base_addr=seg.vaddr, arch=self.arch, entry_point=0, force_rebase=True)
            self.child_objects.append(obj)

        self.mapped_base = 0
        self._max_addr = 0
        self.has_memory = False
        if self.loader.main_object is self:
            self.loader.main_object = None



auxv_codes = {
 0x0: 'AT_NULL',
 0x1: 'AT_IGNORE',
 0x2: 'AT_EXECFD',
 0x3: 'AT_PHDR',
 0x4: 'AT_PHENT',
 0x5: 'AT_PHNUM',
 0x6: 'AT_PAGESZ',
 0x7: 'AT_BASE',
 0x8: 'AT_FLAGS',
 0x9: 'AT_ENTRY',
 0xa: 'AT_NOTELF',
 0xb: 'AT_UID',
 0xc: 'AT_EUID',
 0xd: 'AT_GID',
 0xe: 'AT_EGID',
 0x11: 'AT_CLKTCK',
 0xf: 'AT_PLATFORM',
 0x10: 'AT_HWCAP',
 0x12: 'AT_FPUCW',
 0x13: 'AT_DCACHEBSIZE',
 0x14: 'AT_ICACHEBSIZE',
 0x15: 'AT_UCACHEBSIZE',
 0x16: 'AT_IGNOREPPC',
 0x17: 'AT_SECURE',
 0x18: 'AT_BASE_PLATFORM',
 0x19: 'AT_RANDOM',
 0x1a: 'AT_HWCAP2',
 0x1f: 'AT_EXECFN',
 0x20: 'AT_SYSINFO',
 0x21: 'AT_SYSINFO_EHDR',
 0x22: 'AT_L1I_CACHESHAPE',
 0x23: 'AT_L1D_CACHESHAPE',
 0x24: 'AT_L2_CACHESHAPE',
 0x25: 'AT_L3_CACHESHAPE',
 0x28: 'AT_L1I_CACHESIZE',
 0x29: 'AT_L1I_CACHEGEOMETRY',
 0x2a: 'AT_L1D_CACHESIZE',
 0x2b: 'AT_L1D_CACHEGEOMETRY',
 0x2c: 'AT_L2_CACHESIZE',
 0x2d: 'AT_L2_CACHEGEOMETRY',
 0x2e: 'AT_L3_CACHESIZE',
 0x2f: 'AT_L3_CACHEGEOMETRY'}

register_backend('elfcore', ELFCore)
