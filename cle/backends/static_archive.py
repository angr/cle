from __future__ import annotations

import logging

import arpy

from .backend import Backend, register_backend

log = logging.getLogger(__name__)


class _ARArchive(arpy.Archive):
    """An arpy archive that distinguishes GNU name-table padding from separators."""

    def _Archive__read_gnu_table(self, size: int) -> None:
        """Read an extended filename table without treating trailing NUL padding as a separator."""
        read = getattr(self, "_read", None)
        if read is None:
            read = getattr(self, "read")
        table_data = read(size)
        if len(table_data) != size:
            raise arpy.ArchiveFormatError("file too short to fit the names table")

        # Solaris ar writes slash-newline-terminated names and may pad the table with NULs. arpy 2.3 and newer choose
        # NUL separation whenever any NUL is present, so the padding makes every name after the first unreachable.
        # Treat trailing NULs as padding only when the preceding table is unambiguously slash-newline-terminated.
        # A genuinely NUL-delimited table may itself end in NUL, including a table with only one filename.
        unpadded_data = table_data.rstrip(b"\x00")
        newline_entries = unpadded_data.split(b"\n")
        newline_table = (
            b"\x00" not in unpadded_data
            and len(newline_entries) > 1
            and all(not filename or filename.endswith(b"/") for filename in newline_entries)
        )
        if b"\x00" in table_data and newline_table:
            table_data = unpadded_data
            separator = b"\n"
        else:
            separator = b"\x00" if b"\x00" in table_data else b"\n"

        # arpy <= 2.3 resolves through this eager index.
        self.gnu_table = {}
        position = 0
        for filename in table_data.split(separator):
            self.gnu_table[position] = filename.removesuffix(b"/")
            position += len(filename) + 1

        # arpy >= 2.4 resolves lazily through these fields. They do not exist in the older arpy versions that cle
        # supports, so initialize them only when a GNU table is actually read.
        # pylint: disable=attribute-defined-outside-init
        setattr(self, "gnu_table_data", table_data)
        setattr(self, "gnu_table_separator", separator)
        setattr(self, "gnu_name_cache", {})
        # pylint: enable=attribute-defined-outside-init


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

        ar = _ARArchive(fileobj=self._binary_stream)
        ar.read_all_headers()
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
