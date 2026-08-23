"""Tests for how the loader probes backends against a stream."""

from __future__ import annotations

import io
import os
from unittest import TestCase, main

import arpy

import cle
from cle.errors import CLEError

HERE = os.path.dirname(os.path.realpath(__file__))
TESTS_BASE = os.path.join(HERE, "..", "..", "binaries", "tests")
BSD_ARCHIVE = os.path.join(TESTS_BASE, "aarch64", "bsd_symdef_archive.a")


class ReadSeekOnly:
    """The minimum Loader._load_object_isolated documents: read and seek, no file descriptor."""

    def __init__(self, data: bytes):
        """Wrap the bytes in a buffer this object reads through."""
        self._buffer = io.BytesIO(data)

    def read(self, size=-1):
        """Read from the wrapped buffer."""
        return self._buffer.read(size)

    def seek(self, offset, whence=0):
        """Seek within the wrapped buffer."""
        return self._buffer.seek(offset, whence)

    def tell(self):
        """Report the position in the wrapped buffer."""
        return self._buffer.tell()


def _unclaimed_bytes() -> bytes:
    """The symbol table of a BSD archive: real bytes that no backend recognises as an object."""
    archive = arpy.Archive(BSD_ARCHIVE)
    archive.read_all_headers()
    member = next(m for name, m in archive.archived_files.items() if b"SYMDEF" in name)
    member.seek(0)
    return member.read()


class TestBackendProbing(TestCase):
    """Probing a stream must report that no backend matched, rather than raising."""

    def test_a_stream_without_a_file_descriptor_is_rejected_cleanly(self):
        """The read/seek dispatch accepts more than the BinaryIO annotation declares."""
        with self.assertRaises(CLEError):
            # Loader is annotated BinaryIO, but _load_object_isolated dispatches on
            # hasattr(read)/hasattr(seek), and cle itself hands it arpy members that
            # have neither fileno nor a BinaryIO base. This is that wider set.
            stream = ReadSeekOnly(_unclaimed_bytes())
            cle.Loader(stream, auto_load_libs=False)  # type: ignore[arg-type]

    def test_a_bytesio_is_rejected_the_same_way(self):
        """A BytesIO already behaves correctly; it is the control for the case above."""
        with self.assertRaises(CLEError):
            cle.Loader(io.BytesIO(_unclaimed_bytes()), auto_load_libs=False)

    def test_an_archive_member_without_a_file_descriptor_is_rejected_cleanly(self):
        """An ar member is one instance of a stream with no file descriptor."""
        with self.assertRaises(CLEError):
            cle.Loader(BSD_ARCHIVE, auto_load_libs=False)


if __name__ == "__main__":
    main()
