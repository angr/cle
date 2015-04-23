import os
from .clexception import CLException
from .archinfo import ArchInfo, Arch
from .memory import Clemory
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

        self._memory = Clemory(self.archinfo) # Private virtual address space, without relocations


    def get_vex_ir_endness(self):
        """
        This returns the endianness of the object in VEX notation
        """
        return 'Iend_LE' if self.archinfo.byte_order == 'LSB' else 'Iend_BE'

    def get_vex_endness(self):
        return 'VexEndnessLE' if self.archinfo.byte_order == 'LSB' else 'VexEndnessBE'

