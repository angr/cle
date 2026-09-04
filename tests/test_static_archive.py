from __future__ import annotations

import os
import tempfile
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

# A MIPS64 big-endian static library indexed by a 64-bit "/SYM64/" symbol table, holding one member.
SYM64_ARCHIVE = os.path.join(TEST_BASE, "tests", "mips64", "sym64_archive.a")

# An ARM static library indexed by an ordinary 32-bit "/" symbol table, with a "//" long filename table.
GNU_ARCHIVE = os.path.join(
    TEST_BASE,
    "tests_src",
    "i2c_master_read-nucleol152re",
    "mbed",
    "TARGET_NUCLEO_L152RE",
    "TOOLCHAIN_GCC_ARM",
    "libmbed.a",
)

# The symbol table is the first member of an archive, so its header follows the 8-byte global header. Inside a 60-byte
# member header the decimal size occupies bytes 48 to 58 and the terminating magic occupies the last two.
FIRST_HEADER = 8
SIZE_FIELD = slice(48, 58)
MAGIC_FIELD = slice(58, 60)


def patched(path: str, header_offset: int, field: slice, value: bytes) -> bytes:
    """
    Read an archive and overwrite one field of the member header at `header_offset`, to get a malformed archive that
    differs from a real one in exactly that field.
    """
    with open(path, "rb") as f:
        data = bytearray(f.read())
    data[header_offset + field.start : header_offset + field.stop] = value
    return bytes(data)


class TestStaticArchive(unittest.TestCase):
    """
    Test the AR backend.
    """

    @staticmethod
    def _load_bytes(data: bytes) -> cle.Loader:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "libtest.a")
            with open(path, "wb") as f:
                f.write(data)
            return cle.Loader(path, auto_load_libs=False)

    @staticmethod
    def _load_archive(path: str, **options) -> cle.StaticArchive:
        """
        Load an archive from disk, which the AR backend has to claim.
        """
        ld = cle.Loader(path, auto_load_libs=False, **options)
        assert isinstance(ld.main_object, cle.StaticArchive)
        return ld.main_object

    def test_symbol_table(self):
        # An ordinary archive must keep loading: the 64-bit symbol table is skipped by name, so nothing else moves.
        # rebase_granularity works around an unrelated R_ARM_THM_CALL range failure on this library, as cle's own error
        # message for it suggests.
        archive = self._load_archive(GNU_ARCHIVE, rebase_granularity=0x1000)
        assert archive.arch.name == "ARMCortexM"
        children = [child.binary_basename for child in archive.child_objects]
        assert children[:3] == ["AnalogIn.o", "BusIn.o", "BusOut.o"]
        # Names too long for the 16-byte header field come out of the "//" table.
        assert "mbed_wait_api_no_rtos.o" in children

    def test_sym64_symbol_table(self):
        archive = self._load_archive(SYM64_ARCHIVE)
        assert archive.arch.name == "MIPS64"
        assert archive.arch.memory_endness == "Iend_BE"
        children = [child.binary_basename for child in archive.child_objects]
        assert children == ["x11_xcb.o"]
        symbols = {symbol.name for symbol in archive.child_objects[0].symbols}
        assert "XGetXCBConnection" in symbols

    def test_bad_header_magic(self):
        # A member header with no terminating magic. arpy raises ArchiveFormatError, which is not a CLEError.
        with self.assertRaises(cle.CLEInvalidBinaryError):
            self._load_bytes(patched(GNU_ARCHIVE, FIRST_HEADER, MAGIC_FIELD, b"XX"))

    def test_sym64_size_past_end(self):
        # A 64-bit symbol table whose header claims a size running past the end of the file. Trusting that size would
        # skip the whole archive and drop every member, so leave the table for arpy, which rejects the archive: it
        # reads "/SYM64/" as a member whose name is an offset into the long filename table and raises ValueError.
        with self.assertRaises(cle.CLEInvalidBinaryError):
            self._load_bytes(patched(SYM64_ARCHIVE, FIRST_HEADER, SIZE_FIELD, b"999999999 "))


if __name__ == "__main__":
    unittest.main()
