from __future__ import annotations

import os

import cle
from cle import MachO
from cle.backends.macho.macho_enums import MachoFiletype
from cle.backends.macho.segment import MachOSegment

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
KEXT = os.path.join(TEST_BASE, "tests", "aarch64", "IPwnKit.macho.kext")


def test_kext_loads():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    assert isinstance(ld.main_object, MachO)
    assert ld.main_object.filetype == MachoFiletype.MH_KEXT_BUNDLE


def test_kext_arch():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    assert ld.main_object.arch.name == "AARCH64"


def test_kext_pic():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    assert ld.main_object.pic is True


def test_kext_base_addr():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    assert ld.main_object.mapped_base == 0


def test_kext_segments():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    mo = ld.main_object
    assert isinstance(mo, MachO)
    segnames = [s.segname for s in mo.segments]
    assert "__TEXT" in segnames
    assert "__TEXT_EXEC" in segnames
    assert "__DATA" in segnames
    assert "__DATA_CONST" in segnames
    assert "__LINKEDIT" in segnames


def test_kext_sections():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    mo = ld.main_object
    assert isinstance(mo, MachO)
    section_names = set()
    for seg in mo.segments:
        assert isinstance(seg, MachOSegment)
        for sec in seg.sections:
            section_names.add((seg.segname, sec.sectname))
    assert ("__TEXT_EXEC", "__text") in section_names
    assert ("__TEXT_EXEC", "__auth_stubs") in section_names
    assert ("__DATA_CONST", "__auth_got") in section_names
    assert ("__DATA_CONST", "__got") in section_names


def test_kext_symbols():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    mo = ld.main_object
    assert len(mo.symbols) > 100
    sym_names = {s.name for s in mo.symbols}
    assert "_kmod_info" in sym_names
    assert "__realmain" in sym_names
    assert "_IPwnKit_start" in sym_names
    assert "_IPwnKit_stop" in sym_names


def test_kext_iokit_class_symbols():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    sym_names = {s.name for s in ld.main_object.symbols}
    assert "__ZN21io_oooverflow_IPwnKit5startEP9IOService" in sym_names
    assert "__ZN31io_oooverflow_IPwnKitUserClient10gMetaClassE" in sym_names


def test_kext_relocations():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    assert len(ld.main_object.relocs) > 0


def test_kext_code_readable():
    ld = cle.Loader(KEXT, auto_load_libs=False)
    mo = ld.main_object
    start_sym = [s for s in mo.symbols if s.name == "_IPwnKit_start" and s.relative_addr != 0]
    assert len(start_sym) > 0
    addr = start_sym[0].relative_addr
    data = mo.memory.load(addr, 4)
    assert len(data) == 4
    assert data != b"\x00\x00\x00\x00"
