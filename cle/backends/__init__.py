import os
import logging
import hashlib
from typing import List, Optional  # pylint:disable=unused-import

import sortedcontainers

import archinfo
from .region import Region, Segment, Section
from .regions import Regions
from .symbol import Symbol, SymbolType
from ..address_translator import AT
from ..memory import Clemory
from ..errors import CLEOperationError, CLEError

l = logging.getLogger(name=__name__)


class FunctionHintSource:
    """
    Enums that describe the source of function hints.
    """
    EH_FRAME = 0
    EXTERNAL_EH_FRAME = 1


class FunctionHint:
    """
    Describes a function hint.

    :ivar int addr:     Address of the function.
    :ivar int size:     Size of the function.
    :ivar source:       Source of this hint.
    :vartype source:    int
    """

    __slots__ = ('addr', 'size', 'source')

    def __init__(self, addr, size, source):
        self.addr = addr
        self.size = size
        self.source = source

    def __repr__(self):
        return "<FuncHint@%#x, %d bytes>" % (self.addr, self.size)


class ExceptionHandling:
    """
    Describes an exception handling.

    Exception handlers are usually language-specific. In C++, it is usually implemented as try {} catch {} blocks.

    :ivar int start_addr:               The beginning of the try block.
    :ivar int size:                     Size of the try block.
    :ivar Optional[int] handler_addr:   Address of the exception handler code.
    :ivar type:                         Type of the exception handler. Optional.
    :ivar Optional[int] func_addr:      Address of the function. Optional.
    """

    __slots__ = ('start_addr', 'size', 'handler_addr', 'type', 'func_addr',)

    def __init__(self, start_addr, size, handler_addr=None, type_=None, func_addr=None):

        self.start_addr = start_addr
        self.size = size
        self.handler_addr = handler_addr
        self.type = type_
        self.func_addr = func_addr

    def __repr__(self):
        if self.handler_addr is not None:
            return "<ExceptionHandling@%#x-%#x: handler@%#x>" % (self.start_addr,
                                                                 self.start_addr + self.size,
                                                                 self.handler_addr)
        else:
            return "<ExceptionHandling@%#x-%#x: no handler>" % (self.start_addr,
                                                                 self.start_addr + self.size)


class Backend:
    """
    Main base class for CLE binary objects.

    An alternate interface to this constructor exists as the static method :meth:`cle.loader.Loader.load_object`

    :ivar binary:           The path to the file this object is loaded from
    :ivar binary_basename:  The basename of the filepath, or a short representation of the stream it was loaded from
    :ivar is_main_bin:      Whether this binary is loaded as the main executable
    :ivar segments:         A listing of all the loaded segments in this file
    :ivar sections:         A listing of all the demarked sections in the file
    :ivar sections_map:     A dict mapping from section name to section
    :ivar imports:          A mapping from symbol name to import relocation
    :ivar resolved_imports: A list of all the import symbols that are successfully resolved
    :ivar relocs:           A list of all the relocations in this binary
    :ivar irelatives:       A list of tuples representing all the irelative relocations that need to be performed. The
                            first item in the tuple is the address of the resolver function, and the second item is the
                            address of where to write the result. The destination address is an RVA.
    :ivar jmprel:           A mapping from symbol name to the address of its jump slot relocation, i.e. its GOT entry.
    :ivar arch:             The architecture of this binary
    :vartype arch:          archinfo.arch.Arch
    :ivar str os:           The operating system this binary is meant to run under
    :ivar int mapped_base:  The base address of this object in virtual memory
    :ivar deps:             A list of names of shared libraries this binary depends on
    :ivar linking:          'dynamic' or 'static'
    :ivar linked_base:      The base address this object requests to be loaded at
    :ivar bool pic:         Whether this object is position-independent
    :ivar bool execstack:   Whether this executable has an executable stack
    :ivar str provides:     The name of the shared library dependancy that this object resolves
    :ivar list symbols:     A list of symbols provided by this object, sorted by address
    :ivar has_memory:       Whether this backend is backed by a Clemory or not. As it stands now, a backend should still
                            define `min_addr` and `max_addr` even if `has_memory` is False.
    """
    is_default = False

    def __init__(self,
            binary,
            binary_stream,
            loader=None,
            is_main_bin=False,
            entry_point=None,
            arch=None,
            base_addr=None,
            force_rebase=False,
            has_memory=True,
            **kwargs):
        """
        :param binary:          The path to the binary to load
        :param binary_stream:   The open stream to this binary. The reference to this will be held until you call close.
        :param is_main_bin:     Whether this binary should be loaded as the main executable
        """
        self.binary = binary
        self._binary_stream = binary_stream
        if self.binary is not None:
            self.binary_basename = os.path.basename(self.binary)
        elif hasattr(self._binary_stream, "name"):
            self.binary_basename = os.path.basename(self._binary_stream.name)
        else:
            self.binary_basename = str(self._binary_stream)

        for k in list(kwargs.keys()):
            if k == 'custom_entry_point':
                entry_point = kwargs.pop(k)
            elif k == 'custom_arch':
                arch = kwargs.pop(k)
            elif k == 'custom_base_addr':
                base_addr = kwargs.pop(k)
            else:
                continue
            l.critical("Deprecation warning: the %s parameter has been renamed to %s", k, k[7:])

        if kwargs != {}:
            l.warning("Unused kwargs for loading binary %s: %s", self.binary, ', '.join(kwargs.keys()))

        self.is_main_bin = is_main_bin
        self.has_memory = has_memory
        self.loader = loader
        self._entry = 0
        self._segments = Regions() # List of segments
        self._sections = Regions() # List of sections
        self.sections_map = {}  # Mapping from section name to section
        self.symbols = sortedcontainers.SortedKeyList(key=self._get_symbol_relative_addr)
        self.imports = {}
        self.resolved_imports = []
        self.relocs = []
        self.irelatives = []    # list of tuples (resolver, destination), dest w/o rebase
        self.jmprel = {}
        self.arch = None
        self.os = None  # Let other stuff override this
        self.compiler = None, None  # compiler name, version
        self._symbol_cache = {}
        # a list of directories to search for libraries specified by the object
        self.extra_load_path = []
        # attributes to enable SimProcedure guessing
        self.guess_simprocs = False
        self.guess_simprocs_hint = None

        # checksums
        self.md5 = None
        self.sha256 = None

        self.mapped_base_symbolic = 0
        # These are set by cle, and should not be overriden manually
        self.mapped_base = self.linked_base = 0 # not to be set manually - used by CLE

        self.deps = []           # Needed shared objects (libraries dependencies)
        self.child_objects = []  # any objects loaded directly out of this
        self.parent_object = None
        self.linking = None # Dynamic or static linking
        self.pic = force_rebase
        self.execstack = False

        # tls info set by backend to communicate with thread manager
        self.tls_used = False
        self.tls_block_size = None
        self.tls_data_size = None
        self.tls_data_start = None
        # tls info set by thread manager
        self.tls_module_id = None
        #self.tls_block_offset = None  # this is an ELF-only attribute

        # exception handling
        # they should be rebased when .rebase() is called
        self.exception_handlings = []  # type: List[ExceptionHandling]

        # Hints
        # they should be rebased when .rebase() is called
        self.function_hints = []  # type: List[FunctionHint]

        # Custom options
        self._custom_entry_point = entry_point
        self._custom_base_addr = base_addr
        self.provides = os.path.basename(self.binary) if self.binary is not None else None

        self.memory = None  # type: Clemory

        # should be set inside `cle.Loader.add_object`
        self._is_mapped = False
        # cached max_addr
        self._max_addr = None
        # cached last section
        self._last_section = None
        # cached last segment
        self._last_segment = None

        if arch is None:
            self.arch = None
        elif isinstance(arch, str):
            self.set_arch(archinfo.arch_from_id(arch))
        elif isinstance(arch, archinfo.Arch):
            self.set_arch(arch)
        elif isinstance(arch, type) and issubclass(arch, archinfo.Arch):
            self.set_arch(arch())
        else:
            raise CLEError("Bad parameter: arch=%s" % arch)

        self._checksum()

    def close(self):
        del self._binary_stream

    def __repr__(self):
        return '<%s Object %s, maps [%#x:%#x]>' % \
               (self.__class__.__name__, self.binary_basename, self.min_addr, self.max_addr)

    def set_arch(self, arch):
        self.arch = arch
        self.memory = Clemory(arch) # Private virtual address space, without relocations

    @property
    def image_base_delta(self):
        return self.mapped_base - self.linked_base

    @property
    def entry(self):
        if self._custom_entry_point is not None:
            return AT.from_lva(self._custom_entry_point, self).to_mva()
        return AT.from_lva(self._entry, self).to_mva()

    @property
    def segments(self):
        return self._segments

    @segments.setter
    def segments(self, v):
        if isinstance(v, list):
            self._segments = Regions(lst=v)
        elif isinstance(v, Regions):
            self._segments = v
        else:
            raise ValueError('Unsupported type %s set as sections.' % type(v))

    @property
    def sections(self):
        return self._sections

    @sections.setter
    def sections(self, v):
        if isinstance(v, list):
            self._sections = Regions(lst=v)
        elif isinstance(v, Regions):
            self._sections = v
        else:
            raise ValueError('Unsupported type %s set as sections.' % type(v))

    @property
    def symbols_by_addr(self):
        l.critical("Deprecation warning: symbols_by_addr is deprecated - use loader.find_symbol() for lookup and .symbols for enumeration")
        return {s.rebased_addr: s for s in self.symbols}

    def rebase(self, new_base):
        """
        Rebase backend's regions to the new base where they were mapped by the loader
        """
        if self._is_mapped:
            # we could rebase an object twice if we really wanted... no need though, right?
            raise CLEOperationError("Image already rebased from %#x to %#x" % (self.linked_base, self.mapped_base))

        self.mapped_base = new_base

        if self.sections:
            self.sections._rebase(self.image_base_delta)
        if self.segments and self.sections is not self.segments:
            self.segments._rebase(self.image_base_delta)

        for handling in self.exception_handlings:
            if handling.func_addr is not None:
                handling.func_addr += self.image_base_delta
            if handling.handler_addr is not None:
                handling.handler_addr += self.image_base_delta
            handling.start_addr += self.image_base_delta

        for hint in self.function_hints:
            hint.addr = hint.addr + self.image_base_delta

    def relocate(self):
        """
        Apply all resolved relocations to memory.

        The meaning of "resolved relocations" is somewhat subtle - there is a linking step which attempts to resolve
        each relocation, currently only present in the main internal loading function since the calculation of which
        objects should be available
        """
        for reloc in self.relocs:
            if reloc.resolved:
                reloc.relocate()

    def contains_addr(self, addr):
        """
        Is `addr` in one of the binary's segments/sections we have loaded? (i.e. is it mapped into memory ?)
        """
        return self.find_loadable_containing(addr) is not None

    def find_loadable_containing(self, addr):
        lookup = self.find_segment_containing if self.segments else self.find_section_containing
        return lookup(addr)

    def find_segment_containing(self, addr):
        """
        Returns the segment that contains `addr`, or ``None``.
        """
        if self._last_segment is not None and self._last_segment.contains_addr(addr):
            return self._last_segment

        r = self.segments.find_region_containing(addr)
        if r is not None:
            self._last_segment = r
        return r

    def find_section_containing(self, addr):
        """
        Returns the section that contains `addr` or ``None``.
        """
        if self._last_section is not None and self._last_section.contains_addr(addr):
            return self._last_section

        r = self.sections.find_region_containing(addr)
        if r is not None:
            self._last_section = r
        return r

    def addr_to_offset(self, addr):
        loadable = self.find_loadable_containing(addr)
        if loadable is not None:
            return loadable.addr_to_offset(addr)
        else:
            return None

    def offset_to_addr(self, offset):
        if self.segments:
            for s in self.segments:
                if s.contains_offset(offset):
                    return s.offset_to_addr(offset)
        else:
            for s in self.sections:
                if s.contains_offset(offset):
                    return s.offset_to_addr(offset)
        return None

    @property
    def min_addr(self):
        """
        This returns the lowest virtual address contained in any loaded segment of the binary.
        """
        # Loader maps the object at chosen mapped base anyway and independently of the internal structure
        return self.mapped_base

    @property
    def max_addr(self):
        """
        This returns the highest virtual address contained in any loaded segment of the binary.
        """

        if self._max_addr is None:
            out = self.mapped_base
            if self.segments or self.sections:
                out = max(map(lambda x: x.max_addr, self.segments or self.sections))
            self._max_addr = out - self.mapped_base
        return self._max_addr + self.mapped_base

    @property
    def initializers(self): # pylint: disable=no-self-use
        """
        Stub function. Should be overridden by backends that can provide initializer functions that ought to be run
        before execution reaches the entry point. Addresses should be rebased.
        """
        return []

    @property
    def finalizers(self): # pylint: disable=no-self-use
        """
        Stub function. Like initializers, but with finalizers.
        """
        return []

    @property
    def threads(self):  # pylint: disable=no-self-use
        """
        If this backend represents a dump of a running program, it may contain one or more thread contexts, i.e.
        register files. This property should contain a list of names for these threads, which should be unique.
        """
        return []

    def thread_registers(self, thread=None):  # pylint: disable=no-self-use,unused-argument
        """
        If this backend represents a dump of a running program, it may contain one or more thread contexts, i.e.
        register files. This method should return the register file for a given thread (as named in ``Backend.threads``)
        as a dict mapping register names (as seen in archinfo) to numbers. If the thread is not specified, it should
        return the context for a "default" thread. If there are no threads, it should return an empty dict.
        """
        return {}

    def initial_register_values(self):
        """
        Deprecated
        """
        l.critical("Deprecation warning: initial_register_values is deprecated - use backend.thread_registers() instead")
        return self.thread_registers().items()

    def get_symbol(self, name): # pylint: disable=no-self-use,unused-argument
        """
        Stub function. Implement to find the symbol with name `name`.
        """
        if name in self._symbol_cache:
            return self._symbol_cache[name]
        return None

    @staticmethod
    def extract_soname(path): # pylint: disable=unused-argument
        """
        Extracts the shared object identifier from the path, or returns None if it cannot.
        """
        return None

    @classmethod
    def is_compatible(cls, stream):  # pylint:disable=unused-argument
        """
        Determine quickly whether this backend can load an object from this stream
        """
        return False

    @classmethod
    def check_compatibility(cls, spec, obj): # pylint: disable=unused-argument
        """
        Performs a minimal static load of ``spec`` and returns whether it's compatible with other_obj
        """
        return False

    @classmethod
    def check_magic_compatibility(cls, stream): # pylint: disable=unused-argument
        """
        Check if a stream of bytes contains the same magic number as the main object
        """
        return False

    @staticmethod
    def _get_symbol_relative_addr(symbol):
        return symbol.relative_addr

    def _checksum(self):
        """
        Calculate MD5 and SHA256 checksum for the binary.
        """

        if self._binary_stream is not None:
            data = self._binary_stream.read()
            self._binary_stream.seek(0)
            self.md5 = hashlib.md5(data).digest()
            self.sha256 = hashlib.sha256(data).digest()

ALL_BACKENDS = dict()


def register_backend(name, cls):
    ALL_BACKENDS.update({name: cls})


from .elf import ELF, ELFCore, MetaELF
from .pe import PE
#from .idabin import IDABin
from .blob import Blob
from .cgc import CGC, BackedCGC
from .ihex import Hex
from .minidump import Minidump
from .macho import MachO
from .named_region import NamedRegion
from .java.jar import Jar
from .java.apk import Apk
from .java.soot import Soot
from .xbe import XBE
from .static_archive import StaticArchive

try:
    from .binja import BinjaBin
except Exception:  # pylint:disable=broad-except
    l.warning("Binary Ninja is installed in the environment but the BinjaBin backend fails to initialize. Your Binary "
              "Ninja might be too old.",
              exc_info=True)
