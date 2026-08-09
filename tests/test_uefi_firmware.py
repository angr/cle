#!/usr/bin/env python
from __future__ import annotations

import mmap
import os
import struct
import tempfile
import uuid
from io import BytesIO

import arpy
import pytest

import cle
from cle.backends import ALL_BACKENDS
from cle.backends.uefi_firmware import UefiFirmware

FFS2_GUID = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3").bytes_le
LZMA_GUID = uuid.UUID("ee4e5898-3914-4259-9d6e-dc7bd79403cf").bytes_le
FILE_GUID = uuid.UUID("f8a35c0e-1d20-4a1f-9c3c-6a2e0b7d5e41").bytes_le


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
    A stream over part of a file that shares the file's descriptor, the way an archive member does.
    """

    def __init__(self, file, start: int, size: int):
        file.seek(start)
        super().__init__(file.read(size))
        self._file = file

    def fileno(self):
        return self._file.fileno()

    def tell(self):
        return self._pos


def _firmware_volume() -> bytes:
    """
    Build the smallest UEFI firmware volume that carries an LZMA-compressed section.

    A compressed section is what makes this worth building: ``uefi_firmware`` joins the section's preamble to
    its body before decompressing it, and a memoryview of the loader's stream cannot be joined to anything.
    """
    payload = b"\x5d" + b"\x00" * 64
    # EFI_GUID_DEFINED_SECTION: the GUID, the offset of the body from the start of the section, attributes.
    section_body = LZMA_GUID + struct.pack("<HH", 0x1C, 0x01) + payload
    section = struct.pack("<3sB", (len(section_body) + 4).to_bytes(3, "little"), 0x02) + section_body

    file_size = 0x18 + len(section)
    file = struct.pack("<16sHBB3sB", FILE_GUID, 0, 0x02, 0, file_size.to_bytes(3, "little"), 0xF8) + section

    header_size = 0x48
    volume_size = header_size + len(file)
    header = struct.pack(
        "<16s16sQ4sIHHHsB", b"\x00" * 16, FFS2_GUID, volume_size, b"_FVH", 0, header_size, 0, 0, b"\x00", 2
    )
    block_map = struct.pack("<IIII", 1, volume_size, 0, 0)
    return header + block_map + file


def _bsd_archive(members: list[tuple[bytes, bytes]]) -> bytes:
    """
    Build a static archive in the BSD flavor, which stores member names in the member data.
    """
    out = b"!<arch>\n"
    for name, data in members:
        padded_name = name + b"\x00" * (-len(name) % 8)
        payload = padded_name + data
        header = b"%-16s%-12d%-6d%-6d%-8o%-10d\x60\n" % (
            b"#1/%d" % len(padded_name),
            0,
            0,
            0,
            0o100644,
            len(payload),
        )
        out += header + payload + (b"\n" if len(payload) % 2 else b"")
    return out


@pytest.mark.parametrize("backend", [b for b in ALL_BACKENDS.values() if b.is_default], ids=lambda b: b.__name__)
def test_default_backends_probe_a_read_seek_stream(backend):
    """
    Backend detection offers every default backend every stream, so ``is_compatible`` has to answer for a stream
    that is not a file object rather than raising.
    """
    assert backend.is_compatible(MinimalStream(b"\x00" * 64)) is False


def test_is_compatible_with_an_archive_member():
    """
    A BSD symbol index is not an object file, so it is offered to every backend before the load gives up.
    """
    ar = arpy.Archive(fileobj=BytesIO(_bsd_archive([(b"__.SYMDEF SORTED", struct.pack("<I", 0))])))
    ar.read_all_headers()
    members = list(ar.archived_files.values())
    assert len(members) == 1
    assert UefiFirmware.is_compatible(members[0]) is False


def test_load_archive_with_a_symbol_index():
    """
    The symbol index still has no backend that will take it, so the archive does not load. The loader should be
    the one saying so, rather than a probe raising on the way there.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "libsymdef.a")
        with open(path, "wb") as fp:
            fp.write(_bsd_archive([(b"__.SYMDEF SORTED", struct.pack("<I", 0))]))
        with pytest.raises(cle.CLECompatibilityError):
            cle.Loader(path, auto_load_libs=False)


@pytest.mark.parametrize("kind", ["path", "file", "bytesio", "stream"])
def test_load_firmware_volume(kind):
    """
    A firmware volume loads the same way however the loader was given it.
    """
    data = _firmware_volume()
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "firmware.fd")
        with open(path, "wb") as fp:
            fp.write(data)

        if kind == "file":
            with open(path, "rb") as fp:
                ld = cle.Loader(fp, auto_load_libs=False)
        else:
            spec = {"path": path, "bytesio": BytesIO(data), "stream": MinimalStream(data)}[kind]
            ld = cle.Loader(spec, auto_load_libs=False)
        assert isinstance(ld.main_object, UefiFirmware)


def test_to_bytes_maps_a_whole_file_only():
    """
    A stream may share a descriptor with a larger file, in which case mapping the file behind the descriptor
    would hand the parser the wrong bytes.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "container")
        with open(path, "wb") as fp:
            fp.write(b"headerBODYtrailer")
        with open(path, "rb") as fp:
            whole = UefiFirmware._to_bytes(fp)
            assert isinstance(whole, mmap.mmap)
            with whole:
                assert whole[:] == b"headerBODYtrailer"
            assert UefiFirmware._to_bytes(SliceOfFileStream(fp, 6, 4))[:] == b"BODY"


def test_empty_file_is_not_firmware():
    """
    There is nothing to map in an empty file, which is an answer the probe has to give rather than an error.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "empty")
        with open(path, "wb"):
            pass
        with open(path, "rb") as fp:
            assert UefiFirmware.is_compatible(fp) is False
        with pytest.raises(cle.CLECompatibilityError):
            cle.Loader(path, auto_load_libs=False)


if __name__ == "__main__":
    for cls in ALL_BACKENDS.values():
        if cls.is_default:
            test_default_backends_probe_a_read_seek_stream(cls)
    test_is_compatible_with_an_archive_member()
    test_load_archive_with_a_symbol_index()
    for _kind in ["path", "file", "bytesio", "stream"]:
        test_load_firmware_volume(_kind)
    test_to_bytes_maps_a_whole_file_only()
    test_empty_file_is_not_firmware()
