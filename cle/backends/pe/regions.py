from ..region import Section

class PESection(Section):
    """
    Represents a section for the PE format.
    """
    def __init__(self, pe_section, remap_offset=0):
        super(PESection, self).__init__(
            pe_section.Name.decode(),
            pe_section.Misc_PhysicalAddress,
            pe_section.VirtualAddress + remap_offset,
            pe_section.Misc_VirtualSize,
        )

        self.characteristics = pe_section.Characteristics
        self.size_of_raw_data = pe_section.SizeOfRawData

    #
    # Public properties
    #

    @property
    def is_readable(self):
        return self.characteristics & 0x40000000 != 0

    @property
    def is_writable(self):
        return self.characteristics & 0x80000000 != 0

    @property
    def is_executable(self):
        return self.characteristics & 0x20000000 != 0

    @property
    def only_contains_uninitialized_data(self):
        return self.size_of_raw_data == 0
