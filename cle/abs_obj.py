import os
from .clexception import CLException
from .archinfo import ArchInfo, Arch
from .memory import Clemory
from abc import ABCMeta

class Segment(object):
    """ Simple representation of an ELF file segment"""
    def __init__(self, name, vaddr, memsize, filesize, offset):
        self.vaddr = vaddr
        self.memsize = memsize
        self.filesize = filesize
        self.offset = offset
        self.name = name

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

class Symbol(object):
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
    def __init__(self, owner, symbol, addr, r_type, addend=None):
        super(Relocation, self).__init__()
        self.owner_obj = owner
        self.symbol = symbol
        self.addr = addr
        self.type = r_type
        self.is_rela = addend is not None
        self.addend = 0 if addend is None else addend
        self.resolvedby = None
        self.resolved = False
        if self.symbol is not None and self.symbol.is_import:
            self.owner_obj.imports[self.symbol.name] = self

    def resolve(self, obj):
        self.resolvedby = obj
        self.resolved = True
        if self.symbol is not None:
            self.symbol.resolve(obj)

    @property
    def rebased_addr(self):
        return self.addr + self.owner_obj.rebase_addr


class AbsObj(object):
    __metaclass__ = ABCMeta

    """
        Main abstract class for CLE binary objects.
    """

    def __init__(self, binary, **kwargs):
        """
        args: binary
        kwargs: {load=True, custom_base_addr=None, custom_entry_point=None,
                 custom_offset=None}
        """

        # Unfold the kwargs and convert them to class attributes
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

        self.binary = binary
        self.segments = [] # List of segments
        self.imports = {}
        self.symbols = None # Object's symbols

        # These are set by cle, and should not be overriden manually
        self.rebase_addr = 0 # not to be set manually - used by CLE

        self.object_type = None
        self.deps = None # Needed shared objects (libraries dependencies)
        self.linking = None # Dynamic or static linking

        # Custom options
        self.custom_base_addr = None
        self.custom_entry_point = None
        self.custom_offset = None
        self.provides = None

        self.ppc64_initial_rtoc = None

        if not os.path.exists(self.binary):
            raise CLException("The binary file \"%s\" does not exist :(" %
                              self.binary)

        if 'blob' in kwargs.keys():
            if 'custom_arch' in kwargs.keys():
                self.archinfo = Arch(simarch=kwargs['custom_arch'])
                self.simarch = kwargs['custom_arch']
            else:
                self.archinfo = None

        else:
            archinfo = ArchInfo(self.binary)

            self.archinfo = archinfo
            arch_name = archinfo.name
            self.bits_per_addr = archinfo.bits

            # We use qemu's convention for arch names
            self.arch = archinfo.to_qemu_arch(arch_name)
            self.simarch = archinfo.to_simuvex_arch(arch_name)

        self.memory = Clemory(self.archinfo) # Private virtual address space, without relocations


    def get_vex_ir_endness(self):
        """
        This returns the endianness of the object in VEX notation
        """
        return 'Iend_LE' if self.archinfo.byte_order == 'LSB' else 'Iend_BE'

    def get_vex_endness(self):
        return 'VexEndnessLE' if self.archinfo.byte_order == 'LSB' else 'VexEndnessBE'

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

    def in_which_segment(self, vaddr):
        """ What is the segment name containing @vaddr ?"""
        for s in self.segments:
            if s.contains_addr(vaddr):
                return s.name
        return None

    def get_segment(self, vaddr):
        """ Returns the segment that contains @vaddr """
        for s in self.segments:
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

