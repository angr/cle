import os
from .clexception import CLException
from .archinfo import ArchInfo
from abc import ABCMeta


class AbsObj(object):
    __metaclass__ = ABCMeta

    """
        Main abstract class for CLE binary objects.
    """

    def __init__(self, *args, **kwargs):
        """
        args: binary
        kwargs: {load=True, custom_base_addr=None, custom_entry_point=None,
                 custom_offset=None}
        """

        # Unfold the kwargs and convert them to class attributes
        for k,v in kwargs.iteritems():
            setattr(self, k, v)

        self.binary = args[0]
        self.segments = [] # List of segments
        self.memory = {} # Private virtual address space, without relocations
        self.symbols = None # Object's symbols

        # These are set by cle, and should not be overriden manually
        self.rebase_addr = 0 # not to be set manually - used by CLE
        self.entry_point = None # The entry point defined by CLE

        self.object_type = None
        self.deps = None # Needed shared objects (libraries dependencies)

        if not os.path.exists(self.binary):
            raise CLException("The binary file \"%s\" does not exist :(" %
                              self.binary)

        archinfo = ArchInfo(self.binary)
        self.archinfo = archinfo
        arch_name = archinfo.name
        self.bits_per_addr = archinfo.bits

        # We use qemu's convention for arch names
        self.arch = archinfo.to_qemu_arch(arch_name)
        self.simarch = archinfo.to_simuvex_arch(arch_name)
