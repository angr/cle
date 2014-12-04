import os
import struct
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
        self._memory = Clemory() # Private virtual address space, without relocations
        self.symbols = None # Object's symbols

        # These are set by cle, and should not be overriden manually
        self.rebase_addr = 0 # not to be set manually - used by CLE
        self.entry_point = None # The entry point defined by CLE

        self.object_type = None
        self.deps = None # Needed shared objects (libraries dependencies)
        self.linking = None # Dynamic or static linking

        # Custom options
        self.custom_base_addr = None
        self.custom_entry_point = None
        self.custom_offset = None
        self.provides = None

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


    def get_vex_ir_endness(self):
        """
        This returns the endianness of the object in VEX notation
        """
        return 'Iend_LE' if self.archinfo.byte_order == 'LSB' else 'Iend_BE'

    def get_vex_endness(self):
        return 'VexEndnessLE' if self.archinfo.byte_order == 'LSB' else 'VexEndnessBE'

    def _ppc64_abiv1_entry_fix(self):
        """
        On powerpc64, the e_flags elf header entry's lowest two bits determine
        the ABI type. in ABIv1, the entry point given in the elf headers is not
        actually the entry point, but rather the address in memory where there
        exists a pointer to the entry point.

        Utter bollocks, but this function should fix it.
        """

        self.ppc64_initial_rtoc = None
        if self.archinfo.qemu_arch != 'ppc64': return
        if self.elfflags & 3 < 2:
            ep_offset = self.entry_point - self.rebase_addr
            fmt = '<Q' if self.endianness == 'LSB' else '>Q'

            ep_bitstring = ''.join(self._memory[ep_offset + i] for i in xrange(8))
            self.entry_point = struct.unpack(fmt, ep_bitstring)[0]

            rtoc_bitstring = ''.join(self._memory[ep_offset + i + 8] for i in xrange(8))
            self.ppc64_initial_rtoc = struct.unpack(fmt, rtoc_bitstring)[0]
        else:
            pass

