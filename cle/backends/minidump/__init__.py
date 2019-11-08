import archinfo
import ntpath

from minidump import minidumpfile
from minidump.streams import SystemInfoStream

from . import context
from .. import register_backend, Backend
from ..region import Section
from ... memory import Clemory

class MinidumpMissingStreamError(Exception):
    def __init__(self, stream, message=None):
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
                raise ValueError('The minidump architecture is not AMD64 or x86')

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
        """Get an architecture specific thread context object for the specified thread."""
        if self.arch == archinfo.ArchAMD64():
            Context = context.ContextAMD64
        elif self.arch == archinfo.ArchX86():
            Context = context.ContextX86
        else:
            raise NotImplementedError()
        return Context.from_thread_id(self, thread_id)

register_backend('minidump', Minidump)
