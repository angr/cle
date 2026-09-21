from __future__ import annotations

import os

import cle
from cle.backends.elf import ELF

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

# A VMProtect-packed x86-64 ELF. The segment holding its version tables is not laid out at the
# image base plus its own file offset, so DT_VERNEED points at an RVA well past the end of the
# file. Reading the version tables out of the file stream at that RVA fails. See angr/cle#383.
VMPROTECT = os.path.join(TEST_BASE, "tests", "x86_64", "vmprotect_sample1.vmp.bin")


def test_symbol_versions_when_rva_is_not_the_file_offset():
    ld = cle.Loader(VMPROTECT, auto_load_libs=False)
    obj = ld.main_object
    assert isinstance(obj, ELF)

    # Guard the fixture. Most ELFs put the version tables at an RVA that is also a valid file
    # offset, and against one of those this test would pass without covering anything.
    filesize = os.path.getsize(VMPROTECT)
    verneed = obj._dynamic["DT_VERNEED"]
    file_offset = obj.addr_to_offset(verneed)
    assert file_offset is not None
    assert file_offset < filesize < verneed - obj.linked_base

    versions = {sym.version for sym in obj.symbols if sym.version is not None}
    assert {"GLIBC_2.2.5", "GLIBC_2.3", "GLIBCXX_3.4", "CXXABI_1.3"} <= versions

    by_name = {sym.name: sym.version for sym in obj.symbols}
    assert by_name["printf"] == "GLIBC_2.2.5"
    assert by_name["__gxx_personality_v0"] == "CXXABI_1.3"
    assert by_name["_ZNSs6appendEPKcm"] == "GLIBCXX_3.4"


if __name__ == "__main__":
    test_symbol_versions_when_rva_is_not_the_file_offset()
