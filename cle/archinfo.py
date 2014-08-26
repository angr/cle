import os
from ctypes import *
import logging
import subprocess
import simuvex
import pdb
from .clexception import CLException

l = logging.getLogger("cle.archinfo")

class ArchInfo(object):
    """ This class extracts architecture information from ELF binaries using the
        cle_bfd library.
    """

    # There is a dozen of types of mips and arm CPUs reported from libbfd
    mips_names = ["mips:isa32", "mips:3000"]
    ppc_names = ["powerpc:common"]
    arm_names = ["arm", "armv4t"]

    def __init__(self, binary):
        """ Getarchitecture information from the binary file @binary using
        ctypes and cle_bfd.so """
        env_p = os.getenv("VIRTUAL_ENV")
        lib_p = "lib"
        lib = os.path.join(env_p, lib_p, "cle_bfd.so")

        if not os.path.exists(lib):
            raise CLException("Cannot load cle_bfd.so, invalid path:%s" % lib)
        if not os.path.exists(binary):
            raise CLException("Binary %s does not exist" % binary)

        self.lib = cdll.LoadLibrary(lib)
        self.lib.get_bfd_arch_pname.restype = c_char_p

        self.name = self.lib.get_bfd_arch_pname(binary)
        self.bits = self.lib.get_bits_per_addr(binary)
        self.arch_size = self.lib.get_arch_size(binary)

        self.qemu_arch = self.to_qemu_arch(self.name)
        self.simuvex_arch = self.to_simuvex_arch(self.name)
        self.ida_arch = self.to_ida_arch(self.name)


    def to_qemu_arch(self, arch):
        """ We internally use the BFD architecture names.
         This converts names to the convension used by qemu-user to name its
         different qemu-{arch} architectures. """

        if arch == "i386:x86-64":
            return "x86_64"
        elif arch in self.mips_names:
            return "mips"
        elif arch in self.ppc_names:
            return "ppc"
        elif arch in self.arm_names:
            return "arm"
        elif arch == "i386":
            return "i386"

        else:
            raise CLException("Architecture name conversion not implemented yet"
                              "for \"%s\" !" % arch)

    def to_simuvex_arch(self, arch):
        """ This function translates architecture names from the BFD convention
        to the convention used by simuvex """

        if arch == "i386:x86-64":
            return "AMD64"
        elif "mips" in arch and self.arch_size == 32:
            return "MIPS32"
        elif arch in self.ppc_names:
            return "PPC32"
        elif arch in self.arm_names:
            return "ARM"
        elif arch == "i386":
            return "X86"
        # Unsupported architectures:
        elif "mips" in arch and self.arch_size == 64:
            raise CLException("Architecture MIPS 64 bit not supported")
        elif "ppc" in arch and self.arch_size == 64:
            raise CLException("Architecture PPC 64 bit not supported")
        # mipsel
        elif "mips" in arch and self.endianness == "LSB":
            l.info("Warning: arch mipsel detected, make sure you compile VEX "
                   "accordingly")
        else:
            raise CLException("Unknown architecture")

    def to_ida_arch(self, arch):
        if "i386" in arch:
            return "metapc"
        elif "arm" in arch:
            return "armb"
        elif "mips" in arch:
            return "mipsb"
        elif "powerpc" in arch:
            return "ppc"
        else:
            raise CLException("Unknown architecture")

    def get_qemu_cmd(self):
        """ Find the right qemu-{cmd} for the binary's architecture """
        cmd = "qemu-%s" % self.qemu_arch

        # Check if the command actually exists on the system
        s = subprocess.Popen(["which", cmd], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out = s.communicate()
        err = s.returncode

        # Which returns 0 if the command exists
        if (err != 0):
            raise CLException("Cannot find \"%s\", it does not exist or is not"
                              " in PATH :: %s" % (cmd, out))
        else:
            return cmd

    def get_cross_library_path(self):
        """ Returns the path to cross libraries for @arch, suitable for qemu's
        -L option"""

        arch = self.qemu_arch

        if arch == "x86_64":
            return "/usr/x86_64-linux-gnu/"
        elif arch == "ppc":
            return "/usr/powerpc-linux-gnu/"
        elif arch == "mips":
            return "/usr/mips-linux-gnu/"
        elif arch == "arm":
            return "/usr/arm-linux-gnueabi/"
        elif arch == "i386":
            return "/lib32"

    def get_cross_ld_path(self):
        """ LD_LIBRARY_PATH expects "$ARCH_LIB/lib" except for i386..."""
        if self.qemu_arch == "i386":
            return self.get_cross_library_path()
        else:
            return os.path.join(self.get_cross_library_path, "/lib")

    def get_simuvex_obj(self):
        s_arch = self.to_simuvex_arch(self.name)
        if type(s_arch) is str and s_arch in simuvex.Architectures.keys():
            return simuvex.Architectures[s_arch]()
        else:
            raise Exception("cle.archinfo: architecture %s is not in"
                            " simuvex.Architectures" % repr(s_arch))
        # Let's first get a Simuvex.Architectures object
