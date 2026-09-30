from __future__ import annotations

from cle.backends.region import Section


class PESection(Section):
    """
    Represents a section for the PE format.
    """

    def __init__(
        self,
        pe_section,
        remap_offset=0,
        name: str | None = None,
        image_size: int | None = None,
        file_size: int | None = None,
    ):
        super().__init__(
            name or pe_section.Name.decode("latin-1"),  # ensure all bytes can be decoded
            pe_section.PointerToRawData,
            pe_section.VirtualAddress + remap_offset,
            _mapped_size(pe_section, image_size, file_size),
        )

        self.characteristics = pe_section.Characteristics
        self.filesize = pe_section.SizeOfRawData

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
        return self.filesize == 0


def _mapped_size(pe_section, image_size: int | None, file_size: int | None) -> int:
    """
    How many bytes of a section the Windows loader maps.

    ``Misc_VirtualSize`` alone is not it. The loader copies the section's raw data to the
    section's virtual address, so a section whose raw data is larger than its virtual size --
    including one that declares a virtual size of zero, which the PE specification allows -- is
    mapped over the raw size.

    Two things bound the raw size. Only the bytes the file holds are copied, so a section whose
    raw data runs off the end of the file gets no more than the file can supply; that is the same
    reason ``PE._get_memory_mapped_image`` trims such a section, though it works from the adjusted
    ``PointerToRawData`` and this works from the header's own, which is never smaller. And nothing
    past the end of the image the optional header declares is mapped, however far a section
    header's ``SizeOfRawData`` reaches. Both bounds only ever hold the result down toward the
    declared virtual size, so a section never comes out smaller than its ``Misc_VirtualSize``, and
    one starting at or past the end of the file keeps that size and gains nothing.
    """
    raw_size = pe_section.SizeOfRawData
    if file_size is not None:
        raw_size = min(raw_size, max(0, file_size - pe_section.PointerToRawData))
    if image_size is not None:
        raw_size = min(raw_size, max(0, image_size - pe_section.VirtualAddress))
    return max(pe_section.Misc_VirtualSize, raw_size)
