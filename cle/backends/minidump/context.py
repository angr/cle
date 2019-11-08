import archinfo
import ctypes

BYTE    = ctypes.c_uint8
WORD    = ctypes.c_uint16
DWORD   = ctypes.c_uint32
DWORD64 = ctypes.c_uint64

class Context(ctypes.Structure):
    @classmethod
    def for_arch(cls, arch):
        for sub_cls in cls.__subclasses__:
            if sub_cls.arch == arch:
                return sub_cls
        raise ValueError('Unsupported architecture: ' + arch.name)

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
        raise ValueError('The specified thread id was not found')

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
class ContextAMD64(Context):
    arch = archinfo.ArchAMD64()
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
        # ...
    )

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

class X86_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = (
        ('ControlWord', DWORD),
        ('StatusWord', DWORD),
        ('TagWord', DWORD),
        ('ErrorOffset', DWORD),
        ('ErrorSelector', DWORD),
        ('DataOffset', DWORD),
        ('DataSelector', DWORD),
        ('RegisterArea', BYTE * 80),
        ('Cr0NpxState', DWORD)
    )

# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-wow64_context
class ContextX86(Context):
    _fields_ = (
        ('ContextFlags', DWORD),
        ('Dr0', DWORD),
        ('Dr1', DWORD),
        ('Dr2', DWORD),
        ('Dr3', DWORD),
        ('Dr6', DWORD),
        ('Dr7', DWORD),
        ('FloatSave', X86_FLOATING_SAVE_AREA),
        ('SegGs', DWORD),
        ('SegFs', DWORD),
        ('SegEs', DWORD),
        ('SegDs', DWORD),
        ('Edi', DWORD),
        ('Esi', DWORD),
        ('Ebx', DWORD),
        ('Edx', DWORD),
        ('Ecx', DWORD),
        ('Eax', DWORD),
        ('Ebp', DWORD),
        ('Eip', DWORD),
        ('SegCs', DWORD),
        ('EFlags', DWORD),
        ('Esp', DWORD),
        ('SegSs', DWORD),
        ('ExtendedRegisters', BYTE * 512)
    )

    def update_state(self, state):
        state.regs.fs = self.SegFs
        state.regs.gs = self.SegGs
        state.regs.eax = self.Eax
        state.regs.ebx = self.Ebx
        state.regs.ecx = self.Ecx
        state.regs.edx = self.Edx
        state.regs.esp = self.Esp
        state.regs.esi = self.Esi
        state.regs.edi = self.Edi
        state.regs.eip = self.Eip
        state.regs.eflags = self.EFlags
        return state