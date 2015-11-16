from collections import OrderedDict as _ordered_dict
import os

import archinfo
import subprocess
from ..errors import CLECompatibilityError, CLEError
from ..memory import Clemory

import logging
l = logging.getLogger('cle.backends')

class Region(object):
    """
    A region of memory that is mapped in the object's file.

    offset is the offset into the file the region starts
    vaddr (or just addr) is the virtual address
    filesize (or just size) is the size of the region in the file
    memsize (or vsize) is the size of the region when loaded into memory
    """
    def __init__(self, offset, vaddr, size, vsize):
        self.vaddr = vaddr
        self.memsize = vsize
        self.filesize = size
        self.offset = offset

    def contains_addr(self, addr):
        return (addr >= self.vaddr) and (addr < self.vaddr + self.memsize)

    def contains_offset(self, offset):
        return (offset >= self.offset) and (offset < self.offset + self.filesize)

    def addr_to_offset(self, addr):
        offset = addr - self.vaddr + self.offset
        if not self.contains_offset(offset):
            return None
        return offset

    def offset_to_addr(self, offset):
        addr = offset - self.offset + self.vaddr
        if not self.contains_addr(addr):
            return None
        return addr

    @property
    def max_addr(self):
        return self.vaddr + self.memsize - 1

    @property
    def min_addr(self):
        return self.vaddr

    @property
    def max_offset(self):
        return self.offset + self.filesize - 1

    def min_offset(self):
        return self.offset


class Segment(Region):
    """ Simple representation of an ELF file segment"""
    pass

class Section(Region):
    """ Simple representation of an ELF file section"""
    def __init__(self, name, offset, vaddr, size, sectype, entsize, flags, link, info, align):
        super(Section, self).__init__(offset, vaddr, size, size)
        self.name = name
        self.type = sectype
        self.entsize = entsize
        self.flags = flags
        self.link = link
        self.info = info
        self.align = align

class Symbol(object):
    """
    Representation of a symbol from a binary file. Smart enough to rebase itself.

    There should never be more than one Symbol instance representing a single
    symbol. To make sure of this, only use the get_symbol method in the backend
    objects.
    """
    def __init__(self, owner, name, addr, size, binding, sym_type, sh_info):
        super(Symbol, self).__init__()
        self.owner_obj = owner
        self.name = name
        self.addr = addr
        self.size = size
        self.binding = binding
        self.type = sym_type
        self.sh_info = sh_info if sh_info != 'SHN_UNDEF' else None
        self.resolved = False
        self.resolvedby = None
        if self.addr != 0:
            self.owner_obj.symbols_by_addr[self.addr] = self
            # would be nice if we could populate demangled_names here...
            '''
            demangled = self.demangled_name
            if demangled is not None:
                self.owner_obj.demangled_names[self.name] = demangled
            '''

    def resolve(self, obj):
        self.resolved = True
        self.resolvedby = obj
        self.owner_obj.resolved_imports.append(self)

    @property
    def rebased_addr(self):
        return self.addr + self.owner_obj.rebase_addr

    @property
    def is_import(self):
        return self.sh_info is None and (self.binding == 'STB_GLOBAL' or \
                                         self.binding == 'STB_WEAK' or \
                                         self.binding == 'STT_FUNC')

    @property
    def is_export(self):
        return self.sh_info is not None and (self.binding == 'STB_GLOBAL' or \
                                             self.binding == 'STB_WEAK')

    @property
    def is_function(self):
        return self.type == 'STT_FUNC'

    @property
    def is_weak(self):
        return self.binding == 'STB_WEAK'

    @property
    def demangled_name(self):
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
    """

    def __init__(self, binary, is_main_bin=False, compatible_with=None, filetype='unknown', **kwargs):
        # Unfold the kwargs and convert them to class attributes
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

        self.binary = binary
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

        # These are set by cle, and should not be overriden manually
        self.rebase_addr = 0 # not to be set manually - used by CLE
        self.tls_module_id = None

        self.object_type = None
        self.deps = []           # Needed shared objects (libraries dependencies)
        self.linking = None # Dynamic or static linking
        self.requested_base = None
        self.pic = False
        self.execstack = False

        # Custom options
        self._custom_entry_point = kwargs.get('custom_entry_point', None)
        self.provides = None

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

    def __repr__(self):
        return '<%s Object %s, maps [%#x:%#x]>' % (self.__class__.__name__, os.path.basename(self.binary), self.get_min_addr(), self.get_max_addr())

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
        """ Is @vaddr in one of the binary's segments we have loaded ?
        (i.e., is it mapped into memory ?)
        """
        for i in self.segments:
            if i.contains_addr(addr - self.rebase_addr):
                return True
        return False

    def find_segment_containing(self, vaddr):
        """ Returns the segment that contains @vaddr, or None """
        for s in self.segments:
            if s.contains_addr(vaddr - self.rebase_addr):
                return s

    def find_section_containing(self, vaddr):
        """ Returns the section that contains @vaddr, or None """
        for s in self.sections:
            if s.contains_addr(vaddr - self.rebase_addr):
                return s

    def addr_to_offset(self, addr):
        for s in self.segments:
            if s.contains_addr(addr - self.rebase_addr):
                return s.addr_to_offset(addr - self.rebase_addr)
        return None

    def offset_to_addr(self, offset):
        for s in self.segments:
            if s.contains_offset(offset):
                return s.offset_to_addr(offset) + self.rebase_addr

    def get_min_addr(self):
        """ This returns the lowest virtual address contained in any loaded
        segment of the binary.
        """

        out = None
        for segment in self.segments:
            if out is None or segment.min_addr < out:
                out = segment.min_addr
        return out + self.rebase_addr

    def get_max_addr(self):
        """ This returns the highest virtual address contained in any loaded
        segment of the binary.
        """

        out = None
        for segment in self.segments:
            if out is None or segment.max_addr > out:
                out = segment.max_addr
        return out + self.rebase_addr

    def set_got_entry(self, symbol_name, newaddr):
        '''
         This overrides the address of the function defined by @symbol with
         the new address @newaddr.
         This is used to call simprocedures instead of actual code
        '''

        if symbol_name not in self.imports:
            l.warning("Could not override the address of symbol %s: symbol entry not "
                    "found in GOT", symbol_name)
            return

        self.memory.write_addr_at(self.imports[symbol_name].addr, newaddr)

    def get_initializers(self): # pylint: disable=no-self-use
        '''
         Stub function. Should be overridden by backends that can provide
         initializer functions that ought to be run before execution reaches
         the entry point. Addresses should be rebased.
        '''
        return []

    def get_finalizers(self): # pylint: disable=no-self-use
        '''
         Stub function. Like get_initializers, but with finalizers.
        '''
        return []

    def get_symbol(self, name): # pylint: disable=no-self-use,unused-argument
        '''
         Stub function. Implement to find the symbol with name `name`.
        '''
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

