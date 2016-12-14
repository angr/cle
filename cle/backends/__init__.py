import os
import subprocess
from collections import OrderedDict as _ordered_dict

import archinfo
from ..memory import Clemory
from ..errors import CLECompatibilityError, CLEError

try:
    import claripy
except ImportError:
    claripy = None

import logging
l = logging.getLogger('cle.backends')

class Region(object):
    """
    A region of memory that is mapped in the object's file.

    :ivar offset:       The offset into the file the region starts.
    :ivar vaddr:        The virtual address.
    :ivar filesize:     The size of the region in the file.
    :ivar memsize:      The size of the region when loaded into memory.

    The prefix `v-` on a variable or parameter name indicates that it refers to the virtual, loaded memory space,
    while a corresponding variable without the `v-` refers to the flat zero-based memory of the file.

    When used next to each other, `addr` and `offset` refer to virtual memory address and file offset, respectively.
    """
    def __init__(self, offset, vaddr, filesize, memsize):
        self.vaddr = vaddr
        self.memsize = memsize
        self.filesize = filesize
        self.offset = offset

    def contains_addr(self, addr):
        """
        Does this region contain this virtual address?
        """
        return (addr >= self.vaddr) and (addr < self.vaddr + self.memsize)

    def contains_offset(self, offset):
        """
        Does this region contain this offset into the file?
        """
        return (offset >= self.offset) and (offset < self.offset + self.filesize)

    def addr_to_offset(self, addr):
        """
        Convert a virtual memory address into a file offset
        """
        offset = addr - self.vaddr + self.offset
        if not self.contains_offset(offset):
            return None
        return offset

    def offset_to_addr(self, offset):
        """
        Convert a file offset into a virtual memory address
        """
        addr = offset - self.offset + self.vaddr
        if not self.contains_addr(addr):
            return None
        return addr

    @property
    def max_addr(self):
        """
        The maximum virtual address of this region
        """
        return self.vaddr + self.memsize - 1

    @property
    def min_addr(self):
        """
        The minimum virtual address of this region
        """
        return self.vaddr

    @property
    def max_offset(self):
        """
        The maximum file offset of this region
        """
        return self.offset + self.filesize - 1

    def min_offset(self):
        """
        The minimum file offset of this region
        """
        return self.offset


class Segment(Region):
    """
    Simple representation of an ELF file segment.
    """
    pass

class Section(Region):
    """
    Simple representation of a loaded section.

    :ivar str name:     The name of the section
    """
    def __init__(self, name, offset, vaddr, size):
        """
        :param str name:    The name of the section
        :param int offset:  The offset into the binary file this section begins
        :param int vaddr:   The address in virtual memory this section begins
        :param int size:    How large this section is
        """
        super(Section, self).__init__(offset, vaddr, size, size)
        self.name = name

    @property
    def is_readable(self):
        """
        Whether this section has read permissions
        """
        raise NotImplementedError()

    @property
    def is_writable(self):
        """
        Whether this section has write permissions
        """
        raise NotImplementedError()

    @property
    def is_executable(self):
        """
        Whether this section has execute permissions
        """
        raise NotImplementedError()

    def __repr__(self):
        return "<%s | offset %#x, vaddr %#x, size %#x>" % (
            self.name if self.name else "Unnamed",
            self.offset,
            self.vaddr,
            self.memsize
        )

class Symbol(object):
    # enum for symbol types
    TYPE_OTHER = 0
    TYPE_NONE = 1
    TYPE_FUNCTION = 2
    TYPE_OBJECT = 3
    TYPE_SECTION = 4

    """
    Representation of a symbol from a binary file. Smart enough to rebase itself.

    There should never be more than one Symbol instance representing a single symbol. To make sure of this, only use
    the :meth:`cle.backends.Backend.get_symbol()` to create new symbols.

    :ivar owner_obj:        The object that contains this symbol
    :vartype owner_obj:     cle.backends.Backend
    :ivar str name:         The name of this symbol
    :ivar int addr:         The address of this symbol
    :iver int size:         The size of this symbol
    :ivar int type:         The type of this symbol as one of SYMBOL.TYPE_*
    :ivar bool resolved:    Whether this import symbol has been resolved to a real symbol
    :ivar resolvedby:       The real symbol this import symbol has been resolve to
    :vartype resolvedby:    None or cle.backends.Symbol
    """
    def __init__(self, owner, name, addr, size, sym_type):
        """
        Not documenting this since if you try calling it, you're wrong.
        """
        super(Symbol, self).__init__()
        self.owner_obj = owner
        self.name = name
        self.addr = addr
        self.size = size
        self.type = sym_type
        self.resolved = False
        self.resolvedby = None
        if (claripy and isinstance(self.addr, claripy.ast.Base)) or self.addr != 0:
            self.owner_obj.symbols_by_addr[self.addr] = self
            # would be nice if we could populate demangled_names here...

            #demangled = self.demangled_name
            #if demangled is not None:
            #    self.owner_obj.demangled_names[self.name] = demangled

    def resolve(self, obj):
        self.resolved = True
        self.resolvedby = obj
        self.owner_obj.resolved_imports.append(self)

    @property
    def rebased_addr(self):
        """
        The address of this symbol in the global memory space
        """
        return self.addr + self.owner_obj.rebase_addr

    @property
    def is_function(self):
        """
        Whether this symbol is a function
        """
        return self.type == Symbol.TYPE_FUNCTION

    # These may be overridden in subclasses
    is_static = False
    is_common = False
    is_import = False
    is_export = False
    is_weak = False

    @property
    def demangled_name(self):
        """
        The name of this symbol, run through a C++ demangler

        Warning: this calls out to the external program `c++filt` and will fail loudly if it's not installed
        """
        # make sure it's mangled
        if self.name.startswith("_Z"):
            name = self.name
            if '@@' in self.name:
                name = self.name.split("@@")[0]
            args = ['c++filt']
            args.append(name)
            pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            demangled = stdout.split("\n")

            if len(demangled) > 0:
                return demangled[0]

        return None

class Backend(object):
    """
    Main base class for CLE binary objects.

    An alternate interface to this constructor exists as the static method :meth:`cle.loader.Loader.load_object`

    :ivar binary:           The path to the file this object is loaded from
    :ivar is_main_bin:      Whether this binary is loaded as the main executable
    :ivar segments:         A listing of all the loaded segments in this file
    :ivar sections:         A listing of all the demarked sections in the file
    :ivar sections_map:     A dict mapping from section name to section
    :ivar symbols_by_addr:  A mapping from address to Symbol
    :ivar imports:          A mapping from symbol name to import symbol
    :ivar resolved_imports: A list of all the import symbols that are successfully resolved
    :ivar relocs:           A list of all the relocations in this binary
    :ivar irelatives:       A list of tuples representing all the irelative relocations that need to be performed. The
                            first item in the tuple is the address of the resolver function, and the second item is the
                            address of where to write the result. The destination address is not rebased.
    :ivar jmprel:           A mapping from symbol name to the address of its jump slot relocation, i.e. its GOT entry.
    :ivar arch:             The architecture of this binary
    :vartype arch:          archinfo.arch.Arch
    :ivar str filetype:     The filetype of this object
    :ivar str os:           The operating system this binary is meant to run under
    :ivar compatible_with:  Another Backend object this object must be compatibile with, or None
    :ivar int rebase_addr:  The base address of this object in virtual memory
    :ivar deps:             A list of names of shared libraries this binary depends on
    :ivar linking:          'dynamic' or 'static'
    :ivar requested_base:   The base address this object requests to be loaded at, or None
    :ivar bool pic:         Whether this object is position-independent
    :ivar bool execstack:   Whether this executable has an executable stack
    :ivar str provides:     The name of the shared library dependancy that this object resolves
    """

    def __init__(self, binary, is_main_bin=False, compatible_with=None, filetype='unknown', filename=None, **kwargs):
        """
        :param binary:          The path to the binary to load
        :param is_main_bin:     Whether this binary should be loaded as the main executable
        :param compatible_with: An optional Backend object to force compatibility with
        :param filetype:        The format of the file to load
        """
        # Unfold the kwargs and convert them to class attributes
        # TODO: do we need to do this anymore?
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

        if hasattr(binary, 'seek') and hasattr(binary, 'read'):
            self.binary = filename
            self.binary_stream = binary
        else:
            self.binary = binary
            try:
                self.binary_stream = open(binary, 'rb')
            except IOError:
                self.binary_stream = None

        self.is_main_bin = is_main_bin
        self._entry = None
        self.segments = [] # List of segments
        self.sections = []      # List of sections
        self.sections_map = {}  # Mapping from section name to section
        self.symbols_by_addr = {}
        self.imports = {}
        self.resolved_imports = []
        self.relocs = []
        self.irelatives = []    # list of tuples (resolver, destination), dest w/o rebase
        self.jmprel = {}
        self.arch = None
        self.filetype = filetype
        self.os = 'windows' if self.filetype == 'pe' else 'unix'
        self.compatible_with = compatible_with
        self._symbol_cache = {}
        self.aslr = kwargs['aslr'] if 'aslr' in kwargs else False

        self.rebase_addr_symbolic = 0
        # These are set by cle, and should not be overriden manually
        self.rebase_addr = 0 # not to be set manually - used by CLE

        self.deps = []           # Needed shared objects (libraries dependencies)
        self.linking = None # Dynamic or static linking
        self.requested_base = None
        self.pic = False
        self.execstack = False

        # Custom options
        self._custom_entry_point = kwargs.get('custom_entry_point', None)
        self.provides = os.path.basename(self.binary) if self.binary is not None else None

        self.memory = None

        custom_arch = kwargs.get('custom_arch', None)
        if custom_arch is None:
            self.arch = None
        elif isinstance(custom_arch, str):
            self.set_arch(archinfo.arch_from_id(custom_arch))
        elif isinstance(custom_arch, archinfo.Arch):
            self.set_arch(custom_arch)
        elif isinstance(custom_arch, type) and issubclass(custom_arch, archinfo.Arch):
            self.set_arch(custom_arch())
        else:
            raise CLEError("Bad parameter: custom_arch=%s" % custom_arch)

    supported_filetypes = []

    def close(self):
        if self.binary_stream is not None:
            self.binary_stream.close()
            self.binary_stream = None

    def __repr__(self):
        if self.binary is not None:
            return '<%s Object %s, maps [%#x:%#x]>' % (self.__class__.__name__, os.path.basename(self.binary), self.get_min_addr(), self.get_max_addr())
        else:
            return '<%s Object from stream, maps [%#x:%#x]>' % (self.__class__.__name__, self.get_min_addr(), self.get_max_addr())

    def set_arch(self, arch):
        if self.compatible_with is not None and self.compatible_with.arch != arch:
            raise CLECompatibilityError("Binary %s not compatible with arch %s" % (self.binary, self.compatible_with.arch))
        self.arch = arch
        self.memory = Clemory(arch) # Private virtual address space, without relocations

    @property
    def entry(self):
        if self._custom_entry_point is not None:
            return self._custom_entry_point + self.rebase_addr
        return self._entry + self.rebase_addr

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
        for s in self.segments:
            if s.contains_addr(addr - self.rebase_addr):
                return s

        return None

    def find_section_containing(self, addr):
        """
        Returns the section that contains `addr` or ``None``.
        """
        for s in self.sections:
            if s.contains_addr(addr - self.rebase_addr):
                return s

        return None

    def addr_to_offset(self, addr):
        loadable = self.find_loadable_containing(addr)

        if loadable is not None:
            return loadable.addr_to_offset(addr - self.rebase_addr)
        else:
            return None

    def offset_to_addr(self, offset):
        if self.segments:
            for s in self.segments:
                if s.contains_offset(offset):
                    return s.offset_to_addr(offset) + self.rebase_addr
        else:
            for s in self.sections:
                if s.contains_offset(offset):
                    return s.offset_to_addr(offset) + self.rebase_addr

        return None

    def get_min_addr(self):
        """
        This returns the lowest virtual address contained in any loaded segment of the binary.
        """

        out = None
        for segment in self.segments:
            if out is None or segment.min_addr < out:
                out = segment.min_addr

        if out is None:
            for section in self.sections:
                if out is None or section.min_addr < out:
                    out = section.min_addr

        if out is None:
            return self.rebase_addr
        else:
            return out + self.rebase_addr

    def get_max_addr(self):
        """
        This returns the highest virtual address contained in any loaded segment of the binary.
        """

        out = None
        for segment in self.segments:
            if out is None or segment.max_addr > out:
                out = segment.max_addr

        if out is None:
            for section in self.sections:
                if out is None or section.max_addr > out:
                    out = section.max_addr

        if out is None:
            return self.rebase_addr
        else:
            return out + self.rebase_addr

    def set_got_entry(self, symbol_name, newaddr):
        """
        This overrides the address of the function defined by *symbol* with the new address *newaddr*. This is used to
        call simprocedures instead of actual code,
        """

        if symbol_name not in self.imports:
            l.warning("Could not override the address of symbol %s: symbol entry not "
                    "found in GOT", symbol_name)
            return

        self.memory.write_addr_at(self.imports[symbol_name].addr, newaddr)

    def get_initializers(self): # pylint: disable=no-self-use
        """
        Stub function. Should be overridden by backends that can provide initializer functions that ought to be run
        before execution reaches the entry point. Addresses should be rebased.
        """
        return []

    def get_finalizers(self): # pylint: disable=no-self-use
        """
        Stub function. Like get_initializers, but with finalizers.
        """
        return []

    def get_symbol(self, name): # pylint: disable=no-self-use,unused-argument
        """
        Stub function. Implement to find the symbol with name `name`.
        """
        if name in self._symbol_cache:
            return self._symbol_cache[name]
        return None

from .elf import ELF
from .elfcore import ELFCore
from .pe import PE
from .idabin import IDABin
from .blob import Blob
from .cgc import CGC
from .backedcgc import BackedCGC
from .metaelf import MetaELF

ALL_BACKENDS = _ordered_dict((
    ('elf', ELF),
    ('elfcore', ELFCore),
    ('pe', PE),
    ('cgc', CGC),
    ('backedcgc', BackedCGC),
    ('ida', IDABin),
    ('blob', Blob)
))
