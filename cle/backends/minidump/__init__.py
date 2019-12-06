import archinfo
import ntpath
import struct

from minidump import minidumpfile
from minidump.streams import SystemInfoStream

from .. import register_backend, Backend
from ..region import Section
from ... memory import Clemory
from ...errors import CLEError, CLEInvalidBinaryError

class MinidumpMissingStreamError(Exception):
    def __init__(self, stream, message=None):
        super(MinidumpMissingStreamError, self).__init__()
        self.message = message
        self.stream = stream

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
                raise MinidumpMissingStreamError('SystemInfo', 'The architecture was not specified')
            arch = self._mdf.sysinfo.ProcessorArchitecture
            if arch == SystemInfoStream.PROCESSOR_ARCHITECTURE.AMD64:
                self.set_arch(archinfo.ArchAMD64())
            elif arch == SystemInfoStream.PROCESSOR_ARCHITECTURE.INTEL:
                self.set_arch(archinfo.ArchX86())
            else:
                # has not been tested with other architectures
                raise CLEError('Loading minidumps is not implemented for this architecture')

        if self._mdf.memory_segments_64 is not None:
            segments = self._mdf.memory_segments_64.memory_segments
        elif self._mdf.memory_segments is not None:
            segments = self._mdf.memory_segments.memory_segments
        else:
            raise MinidumpMissingStreamError('MemoryList', 'The memory segments were not defined')

        for segment in segments:
            clemory = Clemory(self.arch)
            data = segment.read(segment.start_virtual_address, segment.size, self._mdf.file_handle)
            clemory.add_backer(0, data)
            self.memory.add_backer(segment.start_virtual_address, clemory)

        for module in self.modules:
            for segment in segments:
                if segment.start_virtual_address == module.baseaddress:
                    break
            else:
                raise CLEInvalidBinaryError('Missing segment for loaded module: ' + module.name)
            section = Section(module.name, segment.start_file_address, module.baseaddress, module.size)
            self.sections.append(section)
            self.sections_map[ntpath.basename(section.name)] = section
        self.segments = self.sections

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
        return [t.ThreadId for t in self._mdf.threads.threads]

    @property
    def raw_thread_records(self):
        return self._mdf.threads.threads

    def thread_registers(self, thread=None):
        if thread is None:
            thread = self.threads[0]

        for thread_record in self._mdf.threads.threads:
            if thread_record.ThreadId == thread:
                break
        else:
            raise KeyError('The specified thread id was not found')
        self.file_handle.seek(thread_record.ThreadContext.Rva)  # pylint: disable=undefined-loop-variable
        data = self.file_handle.read(thread_record.ThreadContext.DataSize)  # pylint: disable=undefined-loop-variable
        self.file_handle.seek(0)

        if self.arch.name == 'AMD64':
            fmt = 'QQQQQQIIHHHHHHIQQQQQQQQQQQQQQQQQQQQQQQ'
            fmt_registers = {
                'fs':     11, 'gs':  12,
                'eflags': 14, 'rax': 21,
                'rcx':    22, 'rdx': 23,
                'rbx':    24, 'rsp': 25,
                'rbp':    26, 'rsi': 27,
                'rdi':    28, 'r8':  29,
                'r9':     30, 'r10': 31,
                'r11':    32, 'r12': 33,
                'r13':    34, 'r14': 35,
                'r15':    36, 'rip': 37
            }
        elif self.arch.name == 'X86':
            fmt = 'IIIIIII112xIIIIIIIIIIIIIIII512x'
            fmt_registers = {
                'gs':     7,  'fs':  8,
                'edi':    11, 'esi': 12,
                'ebx':    13, 'edx': 14,
                'ecx':    15, 'eax': 16,
                'ebp':    17, 'eip': 18,
                'eflags': 20, 'esp': 21
            }
        else:
            raise CLEError('Deserializing minidump registers is not implemented for this architecture')
        data = data[:struct.calcsize(fmt)]
        members = struct.unpack(fmt, data)
        thread_registers = {}
        for register, position in fmt_registers.items():
            thread_registers[register] = members[position]
        return thread_registers

    def get_thread_registers_by_id(self, thread_id):
        return self.thread_registers(thread_id)

register_backend('minidump', Minidump)
