import logging

try:
    from xbe import Xbe
except ImportError:
    Xbe = None

import archinfo

from ..patched_stream import PatchedStream
from ..errors import CLEError
from . import Backend, register_backend
from .region import Segment, Section

l = logging.getLogger(name=__name__)

class XBESection(Section):
    def __init__(self, name, file_offset, file_size, virtual_addr, virtual_size, xbe_sec):
        """
        :param str name:    The name of the section
        :param int offset:  The offset into the binary file this section begins
        :param int vaddr:   The address in virtual memory this section begins
        :param int size:    How large this section is
        """
        super(XBESection, self).__init__(name, file_offset, virtual_addr, virtual_size)
        self.filesize = file_size
        self._xbe_sec = xbe_sec

    @property
    def is_readable(self):
        """
        Whether this section has read permissions
        """
        return True

    @property
    def is_writable(self):
        """
        Whether this section has write permissions
        """
        return (self._xbe_sec.header.flags & self._xbe_sec.header.FLAG_WRITEABLE) != 0

    @property
    def is_executable(self):
        """
        Whether this section has execute permissions
        """
        return (self._xbe_sec.header.flags & self._xbe_sec.header.FLAG_EXECUTABLE) != 0

    @property
    def only_contains_uninitialized_data(self):
        """
        We load every section in, they're all initialized
        """
        return False

class XBE(Backend):
    """
    The main loader class for statically loading XBE executables.
    """
    is_default = True

    def __init__(self, path, **kwargs):
        if Xbe is None:
            raise CLEError("Run `pip install pyxbe==0.0.2` to support loading XBE files")
        super().__init__(path, **kwargs)
        self.set_arch(archinfo.arch_from_id('x86'))

        self.os = 'xbox'
        if self.binary is None:
            self._xbe = Xbe(data=self.binary_stream.read())
        else:
            self._xbe = Xbe.from_file(path)
        self._entry = self._xbe.entry_addr
        self._image_vmem = bytearray(self._xbe.header.image_size)
        self._min_addr = self._xbe.header.base_addr
        self._max_addr = self._xbe.header.base_addr + self._xbe.header.image_size

        # Add header
        self._add_xbe_section(
            0,
            self._xbe.header.image_header_size,
            self._xbe.header.base_addr,
            self._xbe.header.image_header_size,
            self._xbe.header_data)

        # Add each section
        for _, sec in self._xbe.sections.items():
            self._add_xbe_section(
                sec.header.raw_addr,
                sec.header.raw_size,
                sec.header.virtual_addr,
                sec.header.virtual_size,
                sec.data,
                sec)

        self.memory.add_backer(0, bytes(self._image_vmem))
        self.mapped_base = self.linked_base = self._xbe.header.base_addr

    def _add_xbe_section(self, file_offset, file_size, virtual_addr, virtual_size, backer, sec=None):
        # Copy in section contents
        start = virtual_addr - self._xbe.header.base_addr
        end = start + file_size
        self._image_vmem[start:end] = backer

        # Create a segment and a section
        seg = Segment(file_offset, virtual_addr, file_size, virtual_size)
        self.segments.append(seg)

        if sec is not None:
            sec = XBESection(sec.name, file_offset, file_size, virtual_addr, virtual_size, sec)
            self.sections.append(sec)

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(4)
        stream.seek(0)
        return identstring.startswith(b'XBEH')

    @property
    def min_addr(self):
        return self._min_addr

    @property
    def max_addr(self):
        return self._max_addr

    @classmethod
    def check_compatibility(cls, spec, obj): # pylint: disable=unused-argument
        assert(False)
        return True

    def __getstate__(self):
        if self.binary is None:
            raise ValueError("Can't pickle an object loaded from a stream")

        # Get a copy of our pickleable self
        state = dict(self.__dict__)

        # Trash the unpickleable
        if type(self.binary_stream) is PatchedStream:
            state['binary_stream'].stream = None
        else:
            state['binary_stream'] = None

        return state

    def __setstate__(self, data):

        self.__dict__.update(data)

        if self.binary_stream is None:
            self.binary_stream = open(self.binary, 'rb')
        else:
            self.binary_stream.stream = open(self.binary, 'rb')


register_backend("xbe", XBE)
