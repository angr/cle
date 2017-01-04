import struct

from .elf import ELF
from ..errors import CLEError, CLECompatibilityError

import logging
l = logging.getLogger('cle.elfcore')


class CoreNote(object):
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

    def __repr__(self):
        return "<Note %s %s %#x>" % (self.name, self.n_type, len(self.desc))


class PRStatus(object):
    def __init__(self):
        self.cursig = None
        self.sigpend = None
        self.sighold = None

        self.pid = None
        self.ppid = None
        self.pgrp = None
        self.sid = None

        self.utime_usec = None
        self.stime_usec = None
        self.cutime_usec = None
        self.cstime_usec = None
        self.registers = None

        self.fpvalid = None

        # siginfo
        self.si_signo = None
        self.si_code = None
        self.si_errno = None
        self.registers = None

    @staticmethod
    def parse_prstatus(prstatus, elf):
        result = PRStatus()
        result.__parse_prstatus(prstatus, elf)
        return result

    def __parse_prstatus(self, prstatus, elf):
        """
        Parse out the prstatus, accumulating the general purpose register values. Supports AMD64, X86, ARM, and AARCH64
        at the moment.

        :param prstatus: a note object of type NT_PRSTATUS.
        """

        # TODO: support all architectures angr supports

        # extract siginfo from prstatus
        self.si_signo, self.si_code, self.si_errno = struct.unpack("<3I", prstatus.desc[:12])

        # this field is a short, but it's padded to an int
        self.pr_cursig = struct.unpack("<I", prstatus.desc[12:16])[0]

        arch_bytes = elf.arch.bits / 8
        if arch_bytes == 4:
            fmt = "I"
        elif arch_bytes == 8:
            fmt = "Q"
        else:
            raise CLEError("Architecture must have a bitwidth of either 64 or 32")

        self.pr_sigpend, self.pr_sighold = struct.unpack("<" + (fmt * 2), prstatus.desc[16:16+(2*arch_bytes)])

        attrs = struct.unpack("<IIII", prstatus.desc[16+(2*arch_bytes):16+(2*arch_bytes)+(4*4)])
        self.pr_pid, self.pr_ppid, self.pr_pgrp, self.pr_sid = attrs

        # parse out the 4 timevals
        pos = 16+(2*arch_bytes)+(4*4)
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos+arch_bytes])[0] * 1000
        self.pr_utime_usec = struct.unpack("<" + fmt, prstatus.desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos+arch_bytes])[0] * 1000
        self.pr_stime_usec = struct.unpack("<" + fmt, prstatus.desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos+arch_bytes])[0] * 1000
        self.pr_cutime_usec = struct.unpack("<" + fmt, prstatus.desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2
        usec = struct.unpack("<" + fmt, prstatus.desc[pos:pos+arch_bytes])[0] * 1000
        self.pr_cstime_usec = struct.unpack("<" + fmt, prstatus.desc[pos+arch_bytes:pos+arch_bytes*2])[0] + usec

        pos += arch_bytes * 2

        # parse out general purpose registers
        if elf.arch.name == 'AMD64':
            # register names as they appear in dump
            rnames = ['r15', 'r14', 'r13', 'r12', 'rbp', 'rbx', 'r11', 'r10', 'r9', 'r8', 'rax', 'rcx',
                      'rdx', 'rsi', 'rdi', 'xxx', 'rip', 'cs', 'eflags', 'rsp', 'ss', 'xxx', 'xxx', 'ds', 'es',
                      'fs', 'gs']
            nreg = 27
        elif elf.arch.name == 'X86':
            rnames = ['ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs', 'gs', 'xxx', 'eip',
                      'cs', 'eflags', 'esp', 'ss']
            nreg = 17
        elif elf.arch.name == 'ARMHF' or elf.arch.name == 'ARMEL':
            rnames = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
                      'r14', 'r15', 'xxx', 'xxx']
            nreg = 18
        elif elf.arch.name == 'AARCH64':
            rnames = ['x%d' % i for i in range(32)]
            rnames.append('pc')
            rnames.append('xxx')
            nreg = 34
        elif elf.arch.name == 'MIPS32':
            rnames = ['xxx', 'xxx', 'xxx', 'xxx', 'xxx', 'xxx',
                      'zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
                      't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
                      's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
                      't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra',
                      'lo', 'hi', 'pc', 'bad', 'sr', 'status', 'cuase']
            nreg = 45
        else:
            raise CLECompatibilityError("Architecture '%s' unsupported by ELFCore" % elf.arch.name)

        regvals = []
        for idx in range(pos, pos+nreg*arch_bytes, arch_bytes):
            regvals.append(struct.unpack("<" + fmt, prstatus.desc[idx:idx+arch_bytes])[0])
        self.registers = dict(zip(rnames, regvals))
        del self.registers['xxx']

        pos += nreg * arch_bytes
        self.fpvalid = struct.unpack("<I", prstatus.desc[pos:pos+4])[0]

        if self.fpvalid is not None and (elf.arch.name == 'X86' or elf.arch.name == 'AMD64'):
            if not bool(self.fpvalid):
                l.warning("No SSE registers could be loaded from core file")


class ELFCore(ELF):
    """
    Loader class for ELF core files.
    """

    def __init__(self, binary, **kwargs):
        super(ELFCore, self).__init__(binary, **kwargs)

        self.notes = [ ]

        # prstatus
        self.prstatus = []

        self.__extract_note_info()

    supported_filetypes = ['elfcore']

    def initial_register_values(self):
        return self.registers.iteritems()

    def __extract_note_info(self):
        """
        All meaningful information about the process's state at crashtime is stored in the note segment.
        """
        for seg_readelf in self.reader.iter_segments():
            if seg_readelf.header.p_type == 'PT_NOTE':
                self.__parse_notes(seg_readelf)
                break
        else:
            l.warning("Could not find note segment, cannot initialize registers")

    def __parse_notes(self, seg):
        """
        This exists, because note parsing in elftools is not good.
        """

        blob = seg.data()

        note_pos = 0
        while note_pos < len(blob):
            name_sz, desc_sz, n_type = struct.unpack("<3I", blob[note_pos:note_pos+12])
            name_sz_rounded = (((name_sz + (4 - 1)) / 4) * 4)
            desc_sz_rounded = (((desc_sz + (4 - 1)) / 4) * 4)
            # description size + the rounded name size + header size
            n_size = desc_sz_rounded + name_sz_rounded + 12

            # name_sz includes the null byte
            name = blob[note_pos+12:note_pos+12+name_sz-1]
            desc = blob[note_pos+12+name_sz_rounded:note_pos+12+name_sz_rounded+desc_sz]

            self.notes.append(CoreNote(n_type, name, desc))
            note_pos += n_size

        # prstatus
        self.prstatus = map(
                    lambda x: PRStatus.parse_prstatus(x, self),
                    filter(lambda x: x.n_type == 'NT_PRSTATUS', self.notes))
