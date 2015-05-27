import archinfo
from .errors import CLEOperationError, CLECompatibilityError, CLEError
from .memory import Clemory
from abc import ABCMeta
import os

import logging
l = logging.getLogger('cle.generic')

__all__ = ('Region', 'Segment', 'Section', 'Symbol', 'Relocation', 'AbsObj')

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

class Relocation(object):
    """
    A representation of a relocation in a binary file. Smart enough to
    relocate itself.
    """
    def __init__(self, owner, symbol, addr, r_type, addend=None):
        super(Relocation, self).__init__()
        self.owner_obj = owner
        self.arch = owner.arch
        self.symbol = symbol
        self.addr = addr
        self.type = r_type
        self.is_rela = addend is not None
        self._addend = addend
        self.resolvedby = None
        self.resolved = False
        if self.symbol is not None and self.symbol.is_import:
            self.owner_obj.imports[self.symbol.name] = self

    @property
    def addend(self):
        if self.is_rela:
            return self._addend
        else:
            return self.owner_obj.memory.read_addr_at(self.addr)

    def resolve(self, obj):
        self.resolvedby = obj
        self.resolved = True
        if self.symbol is not None:
            self.symbol.resolve(obj)

    @property
    def rebased_addr(self):
        return self.addr + self.owner_obj.rebase_addr

    def relocate(self, solist):
        """
        Applies this relocation. Will make changes to the memory object of the
        object it came from.

        @param solist       A list of objects from which to resolve symbols
        """
        if self.type == 'mips_local':
            return self.reloc_mips_local()
        elif self.type == 'mips_global':
            return self.reloc_mips_global(solist)
        elif self.type in self.arch.reloc_s:
            return self.reloc_global(solist)
        elif self.type in self.arch.reloc_s_a:
            return self.reloc_absolute(solist)
        elif self.type in self.arch.reloc_b_a:
            return self.reloc_relative()
        elif self.type in self.arch.reloc_copy:
            return self.reloc_copy(solist)
        elif self.type in self.arch.reloc_tls_mod_id:
            return self.reloc_tls_mod_id()
        elif self.type in self.arch.reloc_tls_offset:
            return self.reloc_tls_offset()
        else:
            l.warning("Unknown reloc type: %d", self.type)

    def reloc_global(self, solist):
        if not self.resolve_symbol(solist):
            return False
        self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.rebased_addr)
        return True

    def reloc_absolute(self, solist):
        if not self.resolve_symbol(solist):
            return False
        self.owner_obj.memory.write_addr_at(self.addr, self.resolvedby.rebased_addr)
        return True

    def reloc_relative(self):
        self.owner_obj.memory.write_addr_at(self.addr, self.addend + self.owner_obj.rebase_addr)
        self.resolve(None)
        return True

    def reloc_copy(self, solist):
        if not self.resolve_symbol(solist):
            return False
        val = self.resolvedby.owner_obj.memory.read_addr_at(self.resolvedby.addr)
        self.owner_obj.memory.write_addr_at(self.addr, val)
        return True

    def reloc_tls_mod_id(self):
        self.owner_obj.memory.write_addr_at(self.addr, self.owner_obj.tls_module_id)
        self.resolve(None)
        return True

    @staticmethod
    def reloc_tls_offset():
        return False

    def reloc_mips_global(self, solist):
        if not self.resolve_symbol(solist):
            return False
        #delta = -self.owner_obj._dynamic['DT_MIPS_BASE_ADDRESS']
        addr = self.addr #+ delta
        # this causes crashes when not using the ld_fallback, for some reason
        self.owner_obj.memory.write_addr_at(addr, self.resolvedby.rebased_addr)
        return True

    def reloc_mips_local(self):
        if self.owner_obj.rebase_addr == 0:
            self.resolve(None)
            return True                     # don't touch local relocations on the main bin
        delta = self.owner_obj.rebase_addr - self.owner_obj._dynamic['DT_MIPS_BASE_ADDRESS']
        if delta == 0:
            self.resolve(None)
            return True
        elif delta < 0:
            raise CLEOperationError("We are relocating a MIPS object at a lower address than"
                                    " its static base address. This is weird.")
        val = self.owner_obj.memory.read_addr_at(self.addr)
        if val == 0:
            l.error("Address in local GOT at %#x is 0?", self.rebased_addr)
            return False
        newval = val + delta
        self.owner_obj.memory.write_addr_at(self.addr, newval)
        self.resolve(None)
        return True

    def resolve_symbol(self, solist):
        weak_result = None
        for so in solist:
            symbol = so.get_symbol(self.symbol.name)
            if symbol is not None and symbol.is_export:
                if symbol.binding == 'STB_GLOBAL':
                    self.resolve(symbol)
                    return True
                elif weak_result is None:
                    weak_result = symbol

        if weak_result is not None:
            self.resolve(weak_result)
            return True

        # If that doesn't do it, we also look into local symbols
        for so in solist:
            symbol = so.get_symbol(self.symbol.name)
            if symbol is not None and symbol is not self.symbol and symbol.addr != 0:
                l.warning("Matched %s to local symbol of %s. Is this possible?", self.symbol.name, so.binary)
                self.resolve(symbol)
                return True
        return False

class AbsObj(object):
    __metaclass__ = ABCMeta

    """
        Main abstract class for CLE binary objects.
    """

    def __init__(self, binary, compatible_with=None, filetype='unknown', **kwargs):
        """
        args: binary
        kwargs: {load=True, custom_base_addr=None, custom_entry_point=None,
                 custom_offset=None}
        """

        # Unfold the kwargs and convert them to class attributes
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

        self.binary = binary
        self._entry = None
        self.segments = [] # List of segments
        self.sections = []      # List of sections
        self.sections_map = {}  # Mapping from section name to section
        self.symbols_by_addr = {}
        self.imports = {}
        self.resolved_imports = []
        self.relocs = []
        self.jmprel = {}
        self.symbols = None # Object's symbols
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

        # Custom options
        self._custom_entry_point = kwargs.get('custom_entry_point', None)
        self.provides = None

        self.memory = None
        self.ppc64_initial_rtoc = None

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
        return '<%s Object %s, maps [%#x:%#x]>' % (self.__class__.__name__, os.path.basename(self.binary), self.get_min_addr() + self.rebase_addr, self.get_max_addr() + self.rebase_addr)

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

        WARNING: in the case of relocatable objects (e.g., libraries), this
        function works with relative addresses (wrt the start of the object).
        Remember that statically, the Elf headers define a virtual address of 0
        for relocatable objects.

        If you try to use this function with a runtime address of a relocated
        object, you should consider substracting the rebase_addr value to @addr
        beforehands.
        """
        for i in self.segments:
            if i.contains_addr(addr):
                return True
        return False

    def find_segment_containing(self, vaddr):
        """ Returns the segment that contains @vaddr, or None """
        for s in self.segments:
            if s.contains_addr(vaddr):
                return s

    def find_section_containing(self, vaddr):
        """ Returns the section that contains @vaddr, or None """
        for s in self.sections:
            if s.contains_addr(vaddr):
                return s

    def addr_to_offset(self, addr):
        for s in self.segments:
            if s.contains_addr(addr):
                return s.addr_to_offset(addr)
        return None

    def offset_to_addr(self, offset):
        for s in self.segments:
            if s.contains_offset(offset):
                return s.offset_to_addr(offset)

    def get_min_addr(self):
        """
        Return the virtual address of the segment that has the lowest address.
        WARNING: this is calculated BEFORE rebasing the binaries, therefore,
        this is only relevant to executable files, as shared libraries should always
        have 0 as their text segment load addresseses.
        """

        out = None
        for segment in self.segments:
            if out is None or segment.min_addr < out:
                out = segment.min_addr
        return out

    def get_max_addr(self):
        """ This returns the highest virtual address contained in any loaded
        segment of the binary, BEFORE rebasing.

        NOTE: relocation is taken into consideration by ld, not here.
        """

        out = None
        for segment in self.segments:
            if out is None or segment.max_addr > out:
                out = segment.max_addr
        return out

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

