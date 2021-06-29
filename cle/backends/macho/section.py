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

    def __init__(self, offset, vaddr, size, vsize, segname, sectname, align, reloff, nreloc, flags, r1, r2):
        super().__init__(offset, vaddr, size, vsize)

        self.segname = segname.decode()
        self.sectname = sectname.decode()
        self.align = align
        self.reloff = reloff
        self.nreloc = nreloc
        self.flags = flags
        self.reserved1 = r1
        self.reserved2 = r2

    @property
    def type(self):
        return self.flags & TYPE_MASK

    @property
    def attributes(self):
        return self.flags & ATTRIBUTES_MASK

    def __repr__(self):
        return "<Section: %s (part of Segment: %s)| offset %#x, vaddr %#x, size %#x>" % (
            self.sectname if self.sectname else "Unnamed",
            self.segname,
            self.offset,
            self.vaddr,
            self.memsize
        )
