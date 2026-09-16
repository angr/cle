from __future__ import annotations

import os
import shutil
import struct
import tempfile

import archinfo
import pytest
from elftools.elf.elffile import ELFFile

import cle
from cle.backends.elf.metaelf import MetaELF

TEST_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


def _copy_without_dynamic_strtab(src, dst):
    """
    Copy an ELF file, pointing the sh_link of its .dynamic section at the SHT_NULL section.

    That is how an object with no dynamic string table at all encodes it. pyelftools accepts the
    SHT_NULL target and then asserts, rather than raising ELFError, when it is asked to resolve the
    strings of a dynamic tag.
    """
    shutil.copy(src, dst)
    with open(dst, "r+b") as f:
        reader = ELFFile(f)
        index = next(i for i, sec in enumerate(reader.iter_sections()) if sec["sh_type"] == "SHT_DYNAMIC")
        sh_link_offset = 40 if reader.elfclass == 64 else 24
        f.seek(reader["e_shoff"] + index * reader["e_shentsize"] + sh_link_offset)
        f.write(struct.pack("<I" if reader.little_endian else ">I", 0))


def _set_machine_none(path):
    """Rewrite e_machine to EM_NONE, which sits at offset 18 of both the 32- and 64-bit ELF header."""
    with open(path, "r+b") as f:
        reader = ELFFile(f)
        f.seek(18)
        f.write(struct.pack("<H" if reader.little_endian else ">H", 0))


def test_extract_soname_without_dynamic_strtab():
    with tempfile.TemporaryDirectory() as tempdir:
        # No DT_SONAME, so the string table is never needed and the basename stands in.
        no_soname = os.path.join(tempdir, "cpp_qualified_symbols.so")
        _copy_without_dynamic_strtab(os.path.join(TEST_BASE, "x86_64", "cpp_qualified_symbols.so"), no_soname)
        assert MetaELF.extract_soname(no_soname) == "cpp_qualified_symbols.so"

        # A DT_SONAME that can no longer be resolved is just an unanswerable question.
        unresolvable = os.path.join(tempdir, "liblzma.so.5.6.1")
        _copy_without_dynamic_strtab(os.path.join(TEST_BASE, "x86_64", "liblzma.so.5.6.1"), unresolvable)
        assert MetaELF.extract_soname(unresolvable) is None

        # Loader.find_object() runs the same heuristic on files it has never loaded.
        loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
        assert loader.find_object(no_soname) is None
        assert loader.find_object(unresolvable) is None


def test_extract_soname_reads_dt_soname():
    assert MetaELF.extract_soname(os.path.join(TEST_BASE, "x86_64", "liblzma.so.5.6.1")) == "liblzma.so.5"


def test_load_without_dynamic_strtab():
    # A dynamic object with no dynamic string table, for a machine CLE has no architecture for.
    # It cannot be loaded, but it should fail on that rather than in the soname heuristic or the
    # RELRO check, both of which run first and neither of which needs any string.
    with tempfile.TemporaryDirectory() as tempdir:
        target = os.path.join(tempdir, "no_dynstr.so")
        _copy_without_dynamic_strtab(os.path.join(TEST_BASE, "x86_64", "cpp_qualified_symbols.so"), target)
        _set_machine_none(target)
        with pytest.raises(archinfo.ArchNotFound):
            cle.Loader(target, auto_load_libs=False, main_opts={"backend": "elf"})


if __name__ == "__main__":
    test_extract_soname_without_dynamic_strtab()
    test_extract_soname_reads_dt_soname()
    test_load_without_dynamic_strtab()
