from __future__ import annotations

import logging
from io import SEEK_END, BufferedReader

import arpy

from cle.errors import CLEInvalidBinaryError

from .backend import Backend, register_backend

log = logging.getLogger(__name__)

# An ar member header is 16 bytes of name, 12 + 6 + 6 + 8 of metadata, 10 bytes of decimal size, then this magic.
AR_HEADER_LEN = 60
AR_HEADER_MAGIC = b"`\n"


def _skip_sym64_symbol_table(stream: BufferedReader, offset: int) -> int:
    """
    Return the offset of the first member of an ar archive, skipping the symbol table at ``offset`` if it is the 64-bit
    variant.

    The symbol table is the first member of the archive, named "/" for the 32-bit index and "/SYM64/" for the 64-bit
    one. arpy only knows the first spelling: it classifies "/SYM64/" as a member whose real name lives in the long
    filename table, then raises ValueError parsing "SYM64" as the offset into that table. arpy discards the symbol
    table for either spelling, so skipping the member loses nothing.

    Anything that does not look like a 64-bit symbol table lying inside the file leaves the offset alone, so arpy
    reports malformed archives as usual.
    """
    stream.seek(0, SEEK_END)
    file_len = stream.tell()

    stream.seek(offset)
    header = stream.read(AR_HEADER_LEN)
    if len(header) < AR_HEADER_LEN or header[58:60] != AR_HEADER_MAGIC or header[:16].rstrip() != b"/SYM64/":
        return offset

    try:
        size = int(header[48:58])
    except ValueError:
        return offset

    end = offset + AR_HEADER_LEN + size
    if size < 0 or end > file_len:
        return offset
    return end + end % 2  # members start at an even offset


class StaticArchive(Backend):
    @classmethod
    def is_compatible(cls, stream):
        stream.seek(0)
        return stream.read(8) == b"!<arch>\n"

    is_default = True
    is_outer = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # hack: we are using a loader internal method in a non-kosher way which will cause our children to be
        # marked as the main binary if we are also the main binary
        # work around this by setting ourself here:
        if self.loader._main_object is None:
            self.loader._main_object = self

        try:
            ar = arpy.Archive(fileobj=self._binary_stream)
            ar.next_header_offset = _skip_sym64_symbol_table(self._binary_stream, ar.next_header_offset)
            ar.read_all_headers()
        except (arpy.ArchiveFormatError, arpy.ArchiveAccessError, ValueError) as e:
            raise CLEInvalidBinaryError(f"Malformed static archive {self.binary_basename}") from e

        for name, stream in ar.archived_files.items():
            child = self.loader._load_object_isolated(stream)
            child.binary = child.binary_basename = name.decode()
            child.parent_object = self
            self.child_objects.append(child)

        if self.child_objects:
            self._arch = self.child_objects[0].arch
        else:
            log.warning("Loaded empty static archive?")
        self.has_memory = False
        self.pic = True

        # hack pt. 2
        if self.loader._main_object is self:
            self.loader._main_object = None


register_backend("AR", StaticArchive)
