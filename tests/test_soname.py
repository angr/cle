from __future__ import annotations

import os

import archinfo
import pytest

import cle
from cle.backends.elf.metaelf import MetaELF

TEST_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)
NO_SONAME_INVALID_DYNSTR = os.path.join(TEST_BASE, "x86_64", "no_soname_invalid_dynstr_link.so")
SONAME_INVALID_DYNSTR = os.path.join(TEST_BASE, "x86_64", "soname_invalid_dynstr_link.so")


def test_extract_soname_without_dynamic_strtab():
    # No DT_SONAME, so the string table is never needed and the basename stands in.
    assert MetaELF.extract_soname(NO_SONAME_INVALID_DYNSTR) == os.path.basename(NO_SONAME_INVALID_DYNSTR)

    # A DT_SONAME that can no longer be resolved is just an unanswerable question.
    assert MetaELF.extract_soname(SONAME_INVALID_DYNSTR) is None

    # Loader.find_object() runs the same heuristic on files it has never loaded.
    loader = cle.Loader(os.path.join(TEST_BASE, "x86_64", "fauxware"), auto_load_libs=False)
    assert loader.find_object(NO_SONAME_INVALID_DYNSTR) is None
    assert loader.find_object(SONAME_INVALID_DYNSTR) is None


def test_extract_soname_reads_dt_soname():
    assert MetaELF.extract_soname(os.path.join(TEST_BASE, "x86_64", "liblzma.so.5.6.1")) == "liblzma.so.5"


def test_load_without_dynamic_strtab():
    # A dynamic object with no dynamic string table, for a machine CLE has no architecture for.
    # It cannot be loaded, but it should fail on that rather than in the soname heuristic or the
    # RELRO check, both of which run first and neither of which needs any string.
    with pytest.raises(archinfo.ArchNotFound):
        cle.Loader(NO_SONAME_INVALID_DYNSTR, auto_load_libs=False, main_opts={"backend": "elf"})


if __name__ == "__main__":
    test_extract_soname_without_dynamic_strtab()
    test_extract_soname_reads_dt_soname()
    test_load_without_dynamic_strtab()
