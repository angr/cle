# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).

from .. import Region

TYPE_MASK = 0x000000ff
ATTRIBUTES_MASK = 0xffffff00


class MachOSection(Region):
    """
    Mach-O Section, only defined within the context of a Mach-O Segment.

        - offset is the offset into the file the region starts
        - vaddr (or just addr) is the virtual address
        - filesize (or just size) is the size of the region in the file
        - memsize (or vsize) is the size of the region when loaded into memory
        - segname is the corresponding segment's name without padding
        - sectname is the section's name without padding
        - align is the sections alignment as a power of 2
        - reloff is the file offset to the section's relocation entries
        - nreloc is the number of relocation entries for this section
        - flags is a bit vector containing per-section flags
        - r1 and r2 are values for the reserved1 and reserved2 fields respectively
    """

    def __init__(self, macholib_section):
        offset = macholib_section.offset
        vaddr = macholib_section.addr
        size = macholib_section.size
        vsize = macholib_section.size

        super(MachOSection, self).__init__(offset, vaddr, size, vsize)

        self.segname = macholib_section.segname.decode().strip('\x00')
        self.sectname = macholib_section.sectname.decode().strip('\x00')
        self.align = macholib_section.align
        self.reloff = macholib_section.reloff
        self.nreloc = macholib_section.nreloc
        self.flags = macholib_section.flags
        self.reserved1 = macholib_section.reserved1
        self.reserved2 = macholib_section.reserved2

    @property
    def type(self):
        return self.flags & TYPE_MASK

    @property
    def attributes(self):
        return self.flags & ATTRIBUTES_MASK
