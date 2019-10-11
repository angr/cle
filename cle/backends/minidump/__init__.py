import archinfo
import ctypes
import ntpath

from minidump import minidumpfile
from minidump.streams import SystemInfoStream

from .. import register_backend, Backend
from ..region import Section
from ... memory import Clemory

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
DWORD64 = ctypes.c_uint64
DWORD = ctypes.c_uint32
WORD = ctypes.c_uint16
class _CONTEXT_AMD64(ctypes.Structure):
    _fields_ = (
        ('P1Home', DWORD64),
        ('P2Home', DWORD64),
        ('P3Home', DWORD64),
        ('P4Home', DWORD64),
        ('P5Home', DWORD64),
        ('P6Home', DWORD64),
        ('ContextFlags', DWORD),
        ('MxCsr', DWORD),
        ('SegCs', WORD),
        ('SegDs', WORD),
        ('SegEs', WORD),
        ('SegFs', WORD),
        ('SegGs', WORD),
        ('SegSs', WORD),
        ('EFlags', DWORD),
        ('Dr0', DWORD64),
        ('Dr1', DWORD64),
        ('Dr2', DWORD64),
        ('Dr3', DWORD64),
        ('Dr6', DWORD64),
        ('Dr7', DWORD64),
        ('Rax', DWORD64),
        ('Rcx', DWORD64),
        ('Rdx', DWORD64),
        ('Rbx', DWORD64),
        ('Rsp', DWORD64),
        ('Rbp', DWORD64),
        ('Rsi', DWORD64),
        ('Rdi', DWORD64),
        ('R8', DWORD64),
        ('R9', DWORD64),
        ('R10', DWORD64),
        ('R11', DWORD64),
        ('R12', DWORD64),
        ('R13', DWORD64),
        ('R14', DWORD64),
        ('R15', DWORD64),
        ('Rip', DWORD64),
    )
    @classmethod
    def from_bytes(cls, data):
        inst = cls()
        ctypes.memmove(ctypes.byref(inst), data, ctypes.sizeof(inst))
        return inst

    @classmethod
    def from_thread(cls, md, thread):
        md.file_handle.seek(thread.ThreadContext.Rva)
        data = md.file_handle.read(thread.ThreadContext.DataSize)
        md.file_handle.seek(0)
        return cls.from_bytes(data)

    @classmethod
    def from_thread_id(cls, md, thread_id):
        for thread in md.threads:
            if thread.ThreadId == thread_id:
                return cls.from_thread(md, thread)
        raise ValueError('the specified thread id was not found')

    def update_state(self, state):
        state.regs.fs = self.SegFs
        state.regs.gs = self.SegGs
        state.regs.rax = self.Rax
        state.regs.rbx = self.Rbx
        state.regs.rcx = self.Rcx
        state.regs.rdx = self.Rdx
        state.regs.rsp = self.Rsp
        state.regs.rsi = self.Rsi
        state.regs.rdi = self.Rdi
        for idx in range(8, 16):
            setattr(state.regs, 'r' + str(idx), getattr(self, 'R' + str(idx)))
        state.regs.rip = self.Rip
        state.regs.eflags = self.EFlags
        return state

class Minidump(Backend):
    is_default = True
    def __init__(self, *args, **kwargs):
        super(Minidump, self).__init__(*args, **kwargs)
        self.os = 'windows'
        self.supports_nx = True
        if self.binary is None:
            self._mdf = minidumpfile.MinidumpFile.parse_bytes(self.binary_stream.read())
        else:
            self._mdf = minidumpfile.MinidumpFile.parse(self.binary)

        if self.arch is None:
            if getattr(self._mdf, 'sysinfo', None) is None:
                raise RuntimeError('The architecture was not specified and the minidump is missing the information stream')
            arch = self._mdf.sysinfo.ProcessorArchitecture
            if arch == SystemInfoStream.PROCESSOR_ARCHITECTURE.AMD64:
                self.set_arch(archinfo.ArchAMD64())
            elif arch == SystemInfoStream.PROCESSOR_ARCHITECTURE.INTEL:
                self.set_arch(archinfo.ArchX86())
            else:
                # has not been tested with other architectures
                raise ValueError('The minidump architecture is not AMD64 or x86')

        if self.arch == archinfo.ArchAMD64():
            segments = self._mdf.memory_segments_64.memory_segments
        else:
            segments = self._mdf.memory_segments.memory_segments

        for segment in segments:
            clemory = Clemory(self.arch)
            data = segment.read(segment.start_virtual_address, segment.size, self._mdf.file_handle)
            clemory.add_backer(0, data)
            self.memory.add_backer(segment.start_virtual_address, clemory)

        for module in self.modules:
            section = Section(module.name, None, module.baseaddress, module.size)
            self.sections.append(section)
            self.sections_map[ntpath.basename(section.name)] = section

    def __getstate__(self):
        if self.binary is None:
            raise ValueError("Can't pickle an object loaded from a stream")

        state = dict(self.__dict__)

        state['_mdf'] = None
        state['binary_stream'] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._mdf = minidumpfile.MinidumpFile.parse(self.binary)

    @property
    def file_handle(self):
        return self._mdf.file_handle

    @staticmethod
    def is_compatible(stream):
        identstring = stream.read(4)
        stream.seek(0)
        return identstring == b'MDMP'

    @property
    def modules(self):
        return self._mdf.modules.modules

    @property
    def threads(self):
        return self._mdf.threads.threads

    def get_thread_context_by_id(self, thread_id):
        if self.arch == archinfo.ArchAMD64():
            Context = _CONTEXT_AMD64
        else:
            raise NotImplementedError()
        return Context.from_thread_id(self, thread_id)

register_backend('minidump', Minidump)
