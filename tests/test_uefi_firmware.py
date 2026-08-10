#!/usr/bin/env python
from __future__ import annotations

import mmap
import os
from io import BytesIO
from pathlib import Path

import arpy
import pytest

import cle
from cle.backends import ALL_BACKENDS
from cle.backends.uefi_firmware import UefiFirmware

TESTS_BASE = Path(__file__).resolve().parent.parent.parent / "binaries" / "tests"

# A static library in the BSD flavor, so its first member is a ``__.SYMDEF`` symbol index rather than an
# object file. That member is not an object file, so it is offered to every backend in turn before the
# load gives up, which is how the UEFI probe comes to see an archive member at all.
BSD_ARCHIVE = TESTS_BASE / "aarch64" / "bsd_symdef_archive.a"

# Debian's edk2 build of the ArmVirtQemu platform. It is a single firmware volume holding one file whose
# payload is an LZMA-compressed section; inside that are the 93 AArch64 PE drivers the loader reports as
# child objects. The compression matters: ``uefi_firmware`` joins a compressed section's preamble to its
# body before decompressing, so anything ``_to_bytes`` returns has to support concatenation.
FIRMWARE_VOLUME = TESTS_BASE / "aarch64" / "edk2_armvirtqemu.fd"


class MinimalStream:
    """
    A stream offering exactly what the loader asks of a binary specification: ``read`` and ``seek``.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    def read(self, size=None):
        end = len(self._data) if size is None else self._pos + size
        chunk = self._data[self._pos : end]
        self._pos += len(chunk)
        return chunk

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self._pos = offset
        elif whence == os.SEEK_CUR:
            self._pos += offset
        else:
            self._pos = len(self._data) + offset


class SliceOfFileStream(MinimalStream):
    """
    A stream over part of a file that shares the file's descriptor.

    An archive member is this shape; ``arpy.ArchiveFileData`` withholds ``fileno``, so this adds it to
    describe the case a member proxy would present if it ever offered one.
    """

    def __init__(self, file, start: int, size: int):
        file.seek(start)
        super().__init__(file.read(size))
        self._file = file

    def fileno(self):
        return self._file.fileno()

    def tell(self):
        return self._pos


def _archive_members(path):
    archive = arpy.Archive(str(path))
    archive.read_all_headers()
    return archive, list(archive.archived_files.values())


@pytest.mark.parametrize("backend", [b for b in ALL_BACKENDS.values() if b.is_default], ids=lambda b: b.__name__)
def test_default_backends_probe_a_read_seek_stream(backend):
    """
    Backend detection offers every default backend every stream, so ``is_compatible`` has to answer for a stream
    that is not a file object rather than raising.
    """
    archive, members = _archive_members(BSD_ARCHIVE)
    symbol_index = members[0].read()
    archive.close()
    assert backend.is_compatible(MinimalStream(symbol_index)) is False


def test_is_compatible_with_an_archive_member():
    """
    A BSD symbol index is not an object file, so it is offered to every backend before the load gives up.
    """
    archive, members = _archive_members(BSD_ARCHIVE)
    assert members[0].header.name.rstrip(b"\0") == b"__.SYMDEF SORTED"
    assert UefiFirmware.is_compatible(members[0]) is False
    archive.close()


def test_load_archive_with_a_symbol_index():
    """
    The symbol index still has no backend that will take it, so the archive does not load. The loader should be
    the one saying so, rather than a probe raising on the way there.
    """
    with pytest.raises(cle.CLECompatibilityError, match="Unable to find a loader backend"):
        cle.Loader(str(BSD_ARCHIVE), auto_load_libs=False)


@pytest.mark.parametrize("kind", ["path", "file", "bytesio", "stream"])
def test_load_firmware_volume(kind):
    """
    A firmware volume loads the same way however the loader was given it.
    """
    data = FIRMWARE_VOLUME.read_bytes()
    if kind == "file":
        with open(FIRMWARE_VOLUME, "rb") as fp:
            ld = cle.Loader(fp, auto_load_libs=False)
    else:
        spec = {"path": str(FIRMWARE_VOLUME), "bytesio": BytesIO(data), "stream": MinimalStream(data)}[kind]
        ld = cle.Loader(spec, auto_load_libs=False)

    assert isinstance(ld.main_object, UefiFirmware)
    # The drivers live in the compressed section, so reaching them is what says the whole volume was parsed
    # rather than only recognized.
    names = {child.user_interface_name for child in ld.main_object.child_objects}
    assert {"ArmGicDxe", "BdsDxe", "VariableRuntimeDxe"} <= names
    assert ld.main_object.arch.name == "AARCH64"


def test_to_bytes_maps_a_whole_file_only():
    """
    A stream may share a descriptor with a larger file, in which case mapping the file behind the descriptor
    would hand the parser the wrong bytes.
    """
    archive, members = _archive_members(BSD_ARCHIVE)
    header = members[1].header
    member = members[1].read()
    archive.close()

    with open(BSD_ARCHIVE, "rb") as fp:
        whole = UefiFirmware._to_bytes(fp)
        assert isinstance(whole, mmap.mmap)
        with whole:
            assert whole[:] == BSD_ARCHIVE.read_bytes()
        assert UefiFirmware._to_bytes(SliceOfFileStream(fp, header.file_offset, header.size))[:] == member


def test_empty_file_is_not_firmware(tmp_path):
    """
    There is nothing to map in an empty file, which is an answer the probe has to give rather than an error.
    """
    path = tmp_path / "empty"
    path.write_bytes(b"")
    with open(path, "rb") as fp:
        assert UefiFirmware.is_compatible(fp) is False
    with pytest.raises(cle.CLECompatibilityError):
        cle.Loader(str(path), auto_load_libs=False)


if __name__ == "__main__":
    pytest.main([__file__])
