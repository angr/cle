import struct
import elftools
import logging

from .elf import ELF
from .. import register_backend
from ...errors import CLEError, CLECompatibilityError
from ...memory import Clemory

l = logging.getLogger(name=__name__)

# TODO: yall know struct.unpack_from exists, right? maybe even bitstream?


class CoreNote:
    """
    This class is used when parsing the NOTES section of a core file.
    """
    n_type_lookup = {
            1: 'NT_PRSTATUS',
            2: 'NT_PRFPREG',
            3: 'NT_PRPSINFO',
            4: 'NT_TASKSTRUCT',
            6: 'NT_AUXV',
            0x53494749: 'NT_SIGINFO',
            0x46494c45: 'NT_FILE',
            0x46e62b7f: 'NT_PRXFPREG'
            }

    def __init__(self, n_type, name, desc):
        self.n_type = n_type
        if n_type in CoreNote.n_type_lookup:
            self.n_type = CoreNote.n_type_lookup[n_type]
        self.name = name
        self.desc = desc
        self.filename_lookup = []

    def __repr__(self):
        return "<Note %s %s %#x>" % (self.name, self.n_type, len(self.desc))


class ELFCore(ELF):
    """
    Loader class for ELF core files.
    """
    is_default = True # Tell CLE to automatically consider using the ELFCore backend

    def __init__(self, binary, **kwargs):
        super(ELFCore, self).__init__(binary, **kwargs)

        self.notes = []
        self.__current_thread = None
        self._threads = []
        self.auxv = {}

        self.__extract_note_info()

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
        for seg_readelf in self.reader.iter_segments():
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
            l.warning("This core dump does not contain TLS information. threads will be matched to TLS regions via heuristics")
            pointer_rand = self.auxv['AT_RANDOM'][4:8]
            all_locations = [addr - 0x18 for addr in self.__dummy_clemory.find(pointer_rand) if self.__dummy_clemory.unpack_word(addr - 0x18) == addr - 0x18]
            # the heuristic is that generally threads are allocated with descending tls addresses
            for thread, loc in zip(self._threads, reversed(all_locations)):
                thread['segments'] = {thread['registers']['gs'] >> 3: (loc, 0xfffff, 0x51)}

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
        self.filename_lookup = [(ent.vm_start, ent.vm_end, ent.page_offset, fn) for ent, fn in zip(desc.Elf_Nt_File_Entry, desc.filename)]

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
                    else:
                        value.append(byte)
                        pos += 1
                value = bytes(value)

            self.auxv[code_str] = value

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
