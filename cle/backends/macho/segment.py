# -*-coding:utf8 -*-
# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).

from .. import Region
from .section import MachOSection

class MachOSegment(Region):
    """
    Mach-O Segment

        - offset is the offset into the file the region starts
        - vaddr (or just addr) is the virtual address
        - filesize (or just size) is the size of the region in the file
        - memsize (or vsize) is the size of the region when loaded into memory
        - segname is the segment's name without padding
        - nsect is the number of sections contained in this segment
        - sections is an array of MachOSections
        - flags is a bit vector containing per-segment flags
        - initprot and maxprot are initial and maximum permissions respectively
    """

    def __init__(self, macholib_segment, macholib_sections):
        offset = macholib_segment.fileoff
        vaddr = macholib_segment.vmaddr
        size = macholib_segment.filesize
        vsize = macholib_segment.vmsize

        super(MachOSegment, self).__init__(offset, vaddr, size, vsize)

        self.segname = macholib_segment.segname.decode().strip('\x00') 
        # XXX: Is removing trailing null bytes acceptable? Probably yes
        self.nsect = macholib_segment.nsects
        self.sections = self._create_sections(macholib_sections)
        self.flags = macholib_segment.flags
        self.initprot = macholib_segment.initprot
        self.maxprot = macholib_segment.maxprot

    def _create_sections(self, macholib_sections):
        sections = []
        for sect in macholib_sections:
            sections.append(MachOSection(sect))
        return sections

    def get_section_by_name(self, name):
        """
        Searches for a section by name within this segment
        :param name: Name of the section
        :return: MachOSection or None
        """
        for sec in self.sections:
            if sec.sectname == name:
                return sec
        return None

    def __repr__(self):
        return '<MachoSegment: %s>' % self.segname

    def __getitem__(self, item):
        """
        Syntactic sugar for get_section_by_name
        """
        return self.get_section_by_name(item)

    @property
    def is_readable(self):
        return ((self.initprot | self.maxprot) & 0x01) != 0

    @property
    def is_writable(self):
        return ((self.initprot | self.maxprot) & 0x02) != 0

    @property
    def is_executable(self):
        return ((self.initprot | self.maxprot) & 0x04) != 0
