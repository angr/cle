import os
import logging
import subprocess
import simuvex
import struct
from .clexception import CLException
from elftools.elf import elffile

l = logging.getLogger("cle.archinfo")


class Arch(object):
    """ This class extracts architecture information from ELF binaries using the
        cle_bfd library.
    """

    def __init__(self, name=None, bits=None, arch_size=None, byte_order=None, elfflags=0, simarch=None):
        self.elfflags = elfflags

        if simarch is None:
            self.name = name
            self.bits = bits
            self.arch_size = arch_size
            self.byte_order = byte_order
        else:
            s=simuvex.Architectures[simarch]()
            self.name = s.name.lower()
            self.bits = s.bits
            self.arch_size = self.bits
            self.byte_order = "LSB" if s.memory_endness == "Iend_LE" else "MSB"

    @property
    def qemu_arch(self):
        return self.to_qemu_arch(self.name)

    @property
    def simuvex_arch(self):
        return self.to_simuvex_arch(self.name)

    @property
    def ida_arch(self):
        return self.to_ida_arch(self.name)

    def to_qemu_arch(self, arch):
        """ We internally use the BFD architecture names.
         This converts names to the convension used by qemu-user to name its
         different qemu-{arch} architectures. """

        if arch == "i386:x86-64":
            return "x86_64"
        elif arch == 'mips' and self.byte_order == "MSB":
            return "mips"
        elif arch == 'mips' and self.byte_order == "LSB":
            return "mipsel"
        elif arch == 'powerpc' and self.arch_size == 32:
            return "ppc"
        elif arch == 'powerpc' and self.arch_size == 64:
            return "ppc64"
        elif arch == 'arm':
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
        elif arch == 'powerpc' and self.arch_size == 32:
            return "PPC32"
        elif arch == 'powerpc' and self.arch_size == 64:
            return "PPC64"
        elif arch == 'arm':
            return "ARM"
        elif arch == "i386":
            return "X86"
        # Unsupported architectures:
        elif "mips" in arch and self.arch_size == 64:
            raise CLException("Architecture MIPS 64 bit not supported")
        # mipsel
        elif "mips" in arch and self.byte_order == "LSB":
            l.info("Warning: arch mipsel detected, make sure you compile VEX "
                   "accordingly")
        else:
            raise CLException("Unknown architecture")

    @staticmethod
    def to_ida_arch(arch):
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
        if err != 0:
            raise CLException("Cannot find \"%s\", it does not exist or is not"
                              " in PATH :: %s" % (cmd, out))
        else:
            return cmd


    def _arch_paths(self):
        """ Architecture specific libs paths """

        arch = self.qemu_arch

        if arch == "x86_64":
            return ["/usr/lib/x86_64-linux-gnu/", "/lib/x86_64-linux-gnu/"]
        elif arch in ("ppc", "ppc64"):
            return ["/usr/powerpc-linux-gnu/"]
        elif arch == "mips":
            return ["/usr/mips-linux-gnu/"]
        elif arch == "mipsel":
            return ["/usr/mipsel-linux-gnu/"]
        elif arch == "arm" and self.elfflags & 0x200:
            return ["/usr/arm-linux-gnueabi/"]
        elif arch == "arm":
            return ["/usr/arm-linux-gnueabihf/"]
        elif arch == "i386":
            return ["/lib32"]

        raise CLException("Architecture %s is not supported" % arch)

    def get_cross_library_path(self):
        """ Returns the paths to cross libraries for @arch, suitable for qemu's
        -L option (for LD_LIBRARY_PATH, use get_cross_ld_path())"""

        return ":".join(self._arch_paths())

    def get_unique_name(self):
        arch = self.qemu_arch

        if arch == 'arm':
            if self.elfflags & 0x200:
                return 'armel'
            return 'armhf'
        return arch

    def get_cross_ld_path(self):
        """
        This returns a string of contatenated paths where to look for libs, for
        use e.g., with LD_LIBRARY_PATH.
        """
        path = self._arch_paths()
        if self.qemu_arch == "i386" or self.qemu_arch == "x86_64":
            pass
        elif self.qemu_arch == "ppc64":
            path = map(lambda x: os.path.join(x, "/lib64"), path)
        else:
            path = map(lambda x: os.path.join(x, "/lib"), path)
        return ":".join(path)

    def get_simuvex_obj(self):
        s_arch = self.to_simuvex_arch(self.name)
        if isinstance(s_arch, str) and s_arch in simuvex.Architectures.keys():
            return simuvex.Architectures[s_arch]()
        else:
            raise Exception("cle.archinfo: architecture %s is not in"
                            " simuvex.Architectures" % repr(s_arch))
        # Let's first get a Simuvex.Architectures object

    def got_section_name(self):
        """ Returns the name of the section that holds absolute addresses of
            functions, that is, what we want to update after relocation.
            It varies with the architecture.
            We need this function for the IDA backend.
        """
        # MIPS: .got (normal names) (PS: .extern has crappy @@names)
        # ARM : .got (_ptr name)
        if "mips" in self.name or "arm" in self.name:
            return '.got'

        # PPC 32: .plt (.extern has crappy @@names)
        if "powerpc" in self.name:
            return '.plt'

        # x86 .got.plt
        if "i386" in self.name or 'x86-64' in self.name:
            return '.got.plt'

    def compatible_with(self, arch):
        """ Compare the architecture of self with @arch
            in terms of endianness, bits per address and matching names
            e.g., arm-xxx compatible with arm-yyy

            Note: @arch is another archinfo object
            """

        # Same names
        if self.name == arch.name:
            return True

        if self.byte_order != arch.byte_order:
            return False

        if self.bits != arch.bits:
            return False

        # ARM and MIPS have tons of names, so let's just pattern match
        for i in ["mips", "arm", "powerpc"]:
            if i in arch.name and i in self.name:
                l.warning("Considering %s and %s compatible", self.name, arch.name)
                return True

        return False

    def get_struct_fmt(self):
        """ Stuct format for the current architecture, e.g. returns '>Q' for big
        endian 64 bit
        """
        if self.byte_order == 'MSB':
            c = '>'
        else:
            c = '<'

        if self.bits == 64:
            s = 'Q'
        elif self.bits == 32:
            s = 'I'
        elif self.bits == 16:
            s = 'H'
        return c + s

    def addr_to_bytes(self, addr):
        """
        Conversion of an address to an array of bytes valid for the current
        architecture.
        """
        fmt = self.get_struct_fmt()
        return list(struct.pack(fmt, addr))

    def bytes_to_addr(self, data):
        """
        Conversion of an array of bytes into an address.
        """
        fmt = self.get_struct_fmt()
        return struct.unpack(fmt, ''.join(data))[0]

    def get_global_reloc_type(self):
        return self._reloc_s()

    def get_s_a_reloc_type(self):
        return self._reloc_s_a()

    def get_relative_reloc_type(self):
        return self._reloc_b_a()

    def get_copy_reloc_type(self):
        return self._reloc_copy()

    def get_tls_mod_id_reloc_type(self):
        return self._reloc_tls_mod_id()

    def get_tls_offset_reloc_type(self):
        return self._reloc_tls_offset()

    # From tests on Debian in /lib/xxx and /usr/blah/lib for cross stuff, we can
    # see that the following types of relocations actually show up in the dynamic
    # section, intended for the dynamic linker.

    # amd64 needs types [1, 5, 6, 7, 8, 16, 17, 18]:
    #     R_X86_64_64         S+A but the is always 0
    #     R_X86_64_COPY       NONE (seems like S from the description)
    #     R_X86_64_GLOB_DAT   S
    #     R_X86_64_JUMP_SLOT  S
    #     R_X86_64_RELATIVE   B+A
    #     R_X86_64_DTPMOD64   ELF spec says "described in TLS spec"
    #     R_X86_64_DTPOFF64   -
    #     R_X86_64_TPOFF64    -

    # i386 needs relocation types [1, 6, 8, 14, 35, 36]
    #     R_386_32            S+A, but A is always 0
    #     R_386_GLOB_DAT      S
    #     R_386_RELATIVE      B+A
    #     R_386_TLS_TPOFF     doesn't exist in ELF spec but present in TLS supplement
    #     R_386_TLS_DTPMOD32  -
    #     R_386_TLS_DTPOFF32  -

    # ppc needs relocation types [1, 20, 21, 22, 68, 73, 78]
    #     R_PPC_ADDR32        S+A (but same bullshit as x86, A is always 0)
    #     R_PPC_GLOB_DAT      S+A (A is always 0 too...)
    #     R_PPC_JMP_SLOT      the spec redirects to a description saying that it's
    #                         the address of the external function (the spec of
    #                         other architectures call that S)...
    #     R_PPC_RELATIVE      B+A
    #     R_PPC_DTPMOD32      doesn't exist in ELF spec, TLS stuff
    #     R_PPC_TPREL32       -
    #     R_PPC_DTPREL32      -

    # armel needs relocation types [2, 17, 18, 19, 21, 23]
    #     The ELF spec says the dynamic linker should only consider relocation
    #     types 17 to 23. What we get in practice differs...

    #     Note: T is 1 if the target symbol S has type STT_FUNC and the symbol
    #     addresses a Thumb instruction; it is 0 otherwise.

    #     R_ARM_ABS32         S+A|T
    #     R_ARM_TLS_DTPMOD32  - TLS stuff
    #     R_ARM_TLS_DTPOFF32  -
    #     R_ARM_TLS_TPOFF32   -
    #     R_ARM_GLOB_DAT      "resolves to the address of the specified symbol"
    #     R_ARM_RELATIVE      -

    # armhf needs relocation types [2, 17, 18, 19, 21, 23, 160]
    #     Same as armel but 160 is R_ARM_IRELATIVE, and the spec says "Unallocated"

    # ppc64: TODO

    # mips handles relocations differently, and we already support them.

    # According to this, apart from the TLS stuff, we have S and B+A in practice.
    # In case of S+A where A!=0, we should raise an exception, as in practice, I
    # doesn't make any sense.


    def _reloc_s_a(self):
        """
        S+A - update a jump slot with an addend. In practice, we've never seen
        the difference with S.
        """
        if self.name == "i386:x86-64":
            # R_X86_64_64, R_X86_64_32, R_X86_64_32S, R_X86_64_16, R_X86_64_8
            # Thought we've seen only the first one on Linux
            return [ 1, 10, 11, 12, 14 ]

        elif self.name == "i386":
            return [1]

        elif "powerpc" in self.name:
            return [1,20]

        elif "arm" in self.name:
            return [2]

        else:
            return []

    def _reloc_b_a(self):
        """
        B+A - rebase an address
        """
        if self.name == "i386:x86-64":
            #R_X86_64_PC32, R_X86_64_PC16, R_X86_64_PC8, R_X86_64_PC64
            return [8]

        elif self.name == "i386":
            return [8]

        elif "powerpc" in self.name:
            return [22]

        elif "mips" in self.name:
            return [3]
        else:
            return []

    def _reloc_s(self):
        """
        S - update a jump slot with the address of the matching symbol
        """
        if self.name == "i386:x86-64":
            #R_X86_64_GOT32
            return [3, 6, 7]

        elif self.name == "i386":
            return [6]

        elif "powerpc" in self.name:
            return [21]

        elif "arm" in self.name:
            return [21]

        else:
            return []

    def _reloc_copy(self):
        """
        Like S, but copy the actual value of the symbol instead of its addr
        """
        if self.name == "i386:x86-64" or self.name == "i386":
            return [5]
        else:
            return []

    def _reloc_tls_mod_id(self):
        """
        The "module ID" that is passed to __tls_get_addr
        """
        if self.name == "i386:x86-64":
            return [16] # R_X86_64_DTPMOD64
        elif self.name == "i386":
            return [35] # R_386_TLS_DTPMOD32
        elif "arm" in self.name:
            return [17] # R_ARM_TLS_DTPMOD32
        else:
            return []

    def _reloc_tls_offset(self):
        """
        The offset into a TLS block that is passed to __tls_get_addr
        """
        if self.name == "i386:x86-64":
            return [17, 18] # R_X86_64_DTPOFF64, R_X86_64_TPOFF64
        elif self.name == "i386":
            return [36, 37] # R_386_TLS_DTPOFF32, R_386_TLS_TPOFF32
        elif "arm" in self.name:
            return [18, 19] # R_ARM_TLS_DTPOFF32, R_ARM_TLS_TPOFF32
        else:
            return []

    @property
    def dynamic_tag_translation(self):
        if 'mips' in self.name:
            return {
                0x70000001: 'DT_MIPS_RLD_VERSION',
                0x70000005: 'DT_MIPS_FLAGS',
                0x70000006: 'DT_MIPS_BASE_ADDRESS',
                0x7000000a: 'DT_MIPS_LOCAL_GOTNO',
                0x70000011: 'DT_MIPS_SYMTABNO',
                0x70000012: 'DT_MIPS_UNREFEXTNO',
                0x70000013: 'DT_MIPS_GOTSYM',
                0x70000016: 'DT_MIPS_RLD_MAP'
            }
        else:
            return {}

    def translate_dynamic_tag(self, tag):
        try:
            return self.dynamic_tag_translation[tag]
        except KeyError:
            if isinstance(tag, (int, long)):
                l.error("Please look up and add dynamic tag type %#x for %s", tag, self.name)
            return tag

    @property
    def symbol_type_translation(self):
        if self.name == "i386:x86-64":
            return {
                10: 'STT_GNU_IFUNC',
                'STT_LOOS': 'STT_GNU_IFUNC'
            }
        else:
            return {}

    def translate_symbol_type(self, tag):
        try:
            return self.symbol_type_translation[tag]
        except KeyError:
            if isinstance(tag, (int, long)):
                l.error("Please look up and add symbol type %#x for %s", tag, self.name)
            return tag


class ArchInfo(Arch):
    def __init__(self, binary):
        """ Getarchitecture information from the binary file @binary using
        the readelf python lib """
        binary = str(binary)  # Would segfault if utf8
        if not os.path.isfile(binary):
            raise CLException("%s is no file or cannot be found" % binary)
        if not os.access(binary, os.R_OK):
            raise CLException("Insufficient permissions to read file %s" % binary)

        elfread = elffile.ELFFile(open(binary))

        bfdname = {
            'EM_X86_64': 'i386:x86-64',
            'EM_386': 'i386',
            'EM_ARM': 'arm',
            'EM_PPC': 'powerpc',
            'EM_PPC64': 'powerpc',
            'EM_MIPS': 'mips'
        }[elfread.header.e_machine]
        super(ArchInfo, self).__init__(bfdname, elfread.elfclass, elfread.elfclass,
                'LSB' if elfread.little_endian else 'MSB', elfread.header.e_flags)

