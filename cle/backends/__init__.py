import os
import logging
import sortedcontainers

import archinfo
from .region import Region, Segment, Section
from .regions import Regions
from .symbol import Symbol
from ..address_translator import AT
from ..memory import Clemory
from ..errors import CLEOperationError, CLEError

l = logging.getLogger('cle.backends')


class Backend:
    """
    Main base class for CLE binary objects.

    An alternate interface to this constructor exists as the static method :meth:`cle.loader.Loader.load_object`

    :ivar binary:           The path to the file this object is loaded from
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
    """
    is_default = False

    def __init__(self,
            binary,
            loader=None,
            is_main_bin=False,
            filename=None,
            entry_point=None,
            arch=None,
            base_addr=None,
            force_rebase=False,
            has_memory=True,
            **kwargs):
        """
        :param binary:          The path to the binary to load
        :param is_main_bin:     Whether this binary should be loaded as the main executable
        """
        if hasattr(binary, 'seek') and hasattr(binary, 'read'):
            self.binary = filename
            self.binary_stream = binary
        else:
            self.binary = binary
            try:
                self.binary_stream = open(binary, 'rb')
            except IOError:
                self.binary_stream = None

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
        self._entry = None
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
        self.engine_preset = None
        self._symbol_cache = {}
        # a list of directories to search for libraries specified by the object
        self.extra_load_path = []
        # attributes to enable SimProcedure guessing
        self.guess_simprocs = False
        self.guess_simprocs_hint = None

        self.mapped_base_symbolic = 0
        # These are set by cle, and should not be overriden manually
        self.mapped_base = self.linked_base = 0 # not to be set manually - used by CLE

        self.deps = []           # Needed shared objects (libraries dependencies)
        self.linking = None # Dynamic or static linking
        self.pic = force_rebase
        self.execstack = False

        # tls info
        self.tls_used = False
        self.tls_module_id = None
        self.tls_block_offset = None
        self.tls_block_size = None
        self.tls_data_start = None
        self.tls_data_size = None


        # Custom options
        self._custom_entry_point = entry_point
        self._custom_base_addr = base_addr
        self.provides = os.path.basename(self.binary) if self.binary is not None else None

        self.memory = None  # type: Clemory

        # should be set inside `cle.Loader.add_object`
        self._is_mapped = False
        # cached max_addr
        self._max_addr = None

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

    def close(self):
        if self.binary_stream is not None:
            self.binary_stream.close()
            self.binary_stream = None

    def __repr__(self):
        if self.binary is not None:
            return '<%s Object %s, maps [%#x:%#x]>' % \
                   (self.__class__.__name__, os.path.basename(self.binary), self.min_addr, self.max_addr)
        else:
            return '<%s Object from stream, maps [%#x:%#x]>' % \
                   (self.__class__.__name__, self.min_addr, self.max_addr)

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

    def rebase(self):
        """
        Rebase backend's regions to the new base where they were mapped by the loader
        """
        if self._is_mapped:
            raise CLEOperationError("Image already rebased from %#x to %#x" % (self.linked_base, self.mapped_base))
        if self.sections:
            self.sections._rebase(self.image_base_delta)
        if self.segments and self.sections is not self.segments:
            self.segments._rebase(self.image_base_delta)

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
        return self.segments.find_region_containing(addr)

    def find_section_containing(self, addr):
        """
        Returns the section that contains `addr` or ``None``.
        """
        return self.sections.find_region_containing(addr)

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
    def check_compatibility(cls, spec, obj): # pylint: disable=unused-argument
        """
        Performs a minimal static load of ``spec`` and returns whether it's compatible with other_obj
        """
        return False

    @staticmethod
    def _get_symbol_relative_addr(symbol):
        return symbol.relative_addr

ALL_BACKENDS = dict()


def register_backend(name, cls):
    if not hasattr(cls, 'is_compatible'):
        raise TypeError("Backend needs an is_compatible() method")
    ALL_BACKENDS.update({name: cls})


from .elf import ELF, ELFCore, MetaELF
from .pe import PE
#from .idabin import IDABin
from .blob import Blob
from .cgc import CGC, BackedCGC
from .ihex import Hex
from .macho import MachO
from .soot import Soot
from .binja import BinjaBin
