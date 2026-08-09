from __future__ import annotations

import os
import struct
import tempfile
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

OBJECT = os.path.join(TEST_BASE, "tests", "x86_64", "test.o")
LONG_NAME = b"a_member_with_a_long_name.o"


def ar_member(name: bytes, body: bytes) -> bytes:
    """
    Build one ar member: a 60-byte header followed by the body, padded to an even length.
    """
    header = struct.pack(
        "16s 12s 6s 6s 8s 10s 2s",
        name.ljust(16),
        b"0".ljust(12),
        b"0".ljust(6),
        b"0".ljust(6),
        b"0".ljust(8),
        str(len(body)).encode().ljust(10),
        b"`\n",
    )
    return header + body + (b"\n" if len(body) % 2 else b"")


def ar_archive(index_name: bytes, index_width: int) -> bytes:
    """
    Build a GNU ar archive holding two copies of an object file, one named directly and one named through the long
    filename table, indexed by a symbol table whose entries are `index_width` bytes wide.

    "/" with 4-byte entries is the ordinary symbol table. "/SYM64/" with 8-byte entries is the 64-bit one, which GNU ar
    writes for mips64 targets and for archives too large to index with 32-bit offsets.
    """
    with open(OBJECT, "rb") as f:
        body = f.read()

    table = ar_member(b"//", LONG_NAME + b"/\n")
    obj = ar_member(b"test.o/", body)
    long_obj = ar_member(b"/0", body)

    # The symbol table maps a symbol to the offset of the member header defining it, so its own length has to be known
    # before the entries can be filled in.
    names = b"main\x00foo\x00"
    index_len = index_width * 3 + len(names)
    index_end = 8 + 60 + index_len + index_len % 2
    entry = ">Q" if index_width == 8 else ">I"
    index = struct.pack(entry, 2) + struct.pack(entry, index_end + len(table)) * 2 + names

    return b"!<arch>\n" + ar_member(index_name, index) + table + obj + long_obj


class TestStaticArchive(unittest.TestCase):
    """
    Test the AR backend.
    """

    @staticmethod
    def _load(data: bytes) -> cle.Loader:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "libtest.a")
            with open(path, "wb") as f:
                f.write(data)
            return cle.Loader(path, auto_load_libs=False)

    def _check(self, index_name: bytes, index_width: int):
        ld = self._load(ar_archive(index_name, index_width))
        assert isinstance(ld.main_object, cle.StaticArchive)
        assert ld.main_object.arch.name == "AMD64"
        children = [child.binary_basename for child in ld.main_object.child_objects]
        assert children == ["test.o", LONG_NAME.decode()]

    def test_symbol_table(self):
        self._check(b"/", 4)

    def test_sym64_symbol_table(self):
        self._check(b"/SYM64/", 8)

    def test_bad_header_magic(self):
        # A member header with no terminating magic. arpy raises ArchiveFormatError, which is not a CLEError.
        with self.assertRaises(cle.CLEInvalidBinaryError):
            self._load(b"!<arch>\n" + b" " * 60)

    def test_bad_long_name_offset(self):
        # A member whose name is an offset into the long filename table but is not a number, which is how a "/SYM64/"
        # header reaches arpy today. arpy raises ValueError out of int().
        with self.assertRaises(cle.CLEInvalidBinaryError):
            self._load(b"!<arch>\n" + ar_member(b"/nope", b""))

    def test_sym64_size_past_end(self):
        # A 64-bit symbol table whose header claims a size running past the end of the file. Trusting that size would
        # skip the whole archive and drop every member, so report the malformed header instead.
        archive = bytearray(ar_archive(b"/SYM64/", 8))
        size_field = slice(8 + 48, 8 + 58)  # the size field of the first member header, past the 8-byte global header
        archive[size_field] = str(len(archive) * 2).encode().ljust(10)
        with self.assertRaises(cle.CLEInvalidBinaryError):
            self._load(bytes(archive))


if __name__ == "__main__":
    unittest.main()
