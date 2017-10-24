from ..region import Segment, Section


class ELFSegment(Segment):
    """
    Represents a segment for the ELF format.
    """
    def __init__(self, readelf_seg):
        self.flags = readelf_seg.header.p_flags
        super(ELFSegment, self).__init__(readelf_seg.header.p_offset,
                                         readelf_seg.header.p_vaddr,
                                         readelf_seg.header.p_filesz,
                                         readelf_seg.header.p_memsz)

    @property
    def is_readable(self):
        return self.flags & 4 != 0

    @property
    def is_writable(self):
        return self.flags & 2 != 0

    @property
    def is_executable(self):
        return self.flags & 1 != 0


class ELFSection(Section):
    SHF_WRITE = 0x1
    SHF_ALLOC = 0x2
    SHF_EXECINSTR = 0x4
    SHF_STRINGS = 0x20

    def __init__(self, readelf_sec, remap_offset=0):
        super(ELFSection, self).__init__(
            readelf_sec.name,
            readelf_sec.header.sh_offset,
            readelf_sec.header.sh_addr + remap_offset,
            readelf_sec.header.sh_size
        )

        self.type = readelf_sec.header.sh_type
        self.entsize = readelf_sec.header.sh_entsize
        self.flags = readelf_sec.header.sh_flags
        self.link = readelf_sec.header.sh_link
        self.info = readelf_sec.header.sh_info
        self.align = readelf_sec.header.sh_addralign
        self.remap_offset = remap_offset

    @property
    def is_readable(self):
        return True

    @property
    def is_writable(self):
        return self.flags & self.SHF_WRITE != 0

    @property
    def occupies_memory(self):
        return self.flags & self.SHF_ALLOC != 0

    @property
    def is_executable(self):
        return self.flags & self.SHF_EXECINSTR != 0

    @property
    def is_strings(self):
        return self.flags & self.SHF_STRINGS != 0
