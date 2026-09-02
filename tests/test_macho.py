#!/usr/bin/env python
from __future__ import annotations

import ctypes
import logging
import os
import struct
import tempfile
from io import BytesIO

import pytest

import cle
from cle import MachO
from cle.backends.macho.macho_enums import LoadCommands, MachoFiletype, MH_flags, SectionAttributes, SectionType
from cle.backends.macho.section import MachOSection
from cle.backends.macho.structs import DyldImportStruct, dyld_chained_fixups_header
from cle.backends.macho.symbol import (
    LIBRARY_ORDINAL_DYN_LOOKUP,
    LIBRARY_ORDINAL_EXECUTABLE,
    N_EXT,
    N_STAB,
    SYMBOL_TYPE_UNDEF,
)
from cle.errors import CLECompatibilityError

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

SEGMENT_COMMAND_64 = "<2I16s4Q4I"
SEGMENT_COMMAND_64_SIZE = struct.calcsize(SEGMENT_COMMAND_64)

# offsets of mach header fields, and the leading fields of an nlist entry
FILETYPE_OFFSET = 12
FLAGS_OFFSET = 24
NLIST_PREFIX = "<IBBH"  # n_strx, n_type, n_sect, n_desc


def test_fauxware():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.MachO)
    assert ld.main_object.os == "macos"
    assert ld.main_object.entry == 0x100000DE0

    assert sorted(list(ld.main_object.exports_by_name))[-1] == "_sneaky"


# Contributed September 2019 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).
def test_dummy():
    """All-in-one testcase exercising all features in combination for 64 bit binaries"""
    # TODO: Updated with new features

    machofile = os.path.join(TEST_BASE, "tests", "armhf", "dummy.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.MachO)
    macho: MachO = ld.main_object
    expected_segments = [
        # segname, vaddr,vsize,foff,fsize,nsect,flags,
        ("__PAGEZERO", 0x0, 0x100000000, 0, 0, 0, 0),
        ("__TEXT", 0x100000000, 0x8000, 0, 0x8000, 8, 0),
        ("__DATA", 0x100008000, 0x4000, 0x8000, 0x4000, 13, 0),
        ("__LINKEDIT", 0x10000C000, 0x4000, 0xC000, 0x3BA0, 0, 0),
    ]

    expected_sections = {
        # segname=> (secname,segname,vaddr,vsize,foff,align,reloff,nreloc,flags)
        "__TEXT": [
            ("__text", "__TEXT", 0x1000067DC, 0x430, 0x67DC, 0x2, 0, 0, 0x80000400),
            ("__stubs", "__TEXT", 0x100006C0C, 0x78, 0x6C0C, 0x1, 0, 0, 0x80000408),
            (
                "__stub_helper",
                "__TEXT",
                0x100006C84,
                0x90,
                0x6C84,
                0x2,
                0,
                0,
                0x80000400,
            ),
            ("__objc_methname", "__TEXT", 0x100006D14, 0x9DF, 0x6D14, 0, 0, 0, 0x2),
            ("__objc_classname", "__TEXT", 0x1000076F3, 0x3C, 0x76F3, 0, 0, 0, 0x2),
            ("__objc_methtype", "__TEXT", 0x10000772F, 0x7FC, 0x772F, 0, 0, 0, 0x2),
            ("__cstring", "__TEXT", 0x100007F2B, 0x7F, 0x7F2B, 0, 0, 0, 0x2),
            ("__unwind_info", "__TEXT", 0x100007FAC, 0x54, 0x7FAC, 0x2, 0, 0, 0),
        ],
        "__DATA": [
            ("__got", "__DATA", 0x100008000, 0x10, 0x8000, 3, 0, 0, 0x6),
            ("__la_symbol_ptr", "__DATA", 0x100008010, 0x50, 0x8010, 3, 0, 0, 0x7),
            ("__cfstring", "__DATA", 0x100008060, 0x20, 0x8060, 3, 0, 0, 0),
            (
                "__objc_classlist",
                "__DATA",
                0x100008080,
                0x10,
                0x8080,
                3,
                0,
                0,
                0x10000000,
            ),
            ("__objc_protolist", "__DATA", 0x100008090, 0x10, 0x8090, 3, 0, 0, 0),
            ("__objc_imageinfo", "__DATA", 0x1000080A0, 0x8, 0x80A0, 2, 0, 0, 0),
            ("__objc_const", "__DATA", 0x1000080A8, 0xBC0, 0x80A8, 3, 0, 0, 0),
            (
                "__objc_selrefs",
                "__DATA",
                0x100008C68,
                0x18,
                0x8C68,
                3,
                0,
                0,
                0x10000005,
            ),
            (
                "__objc_classrefs",
                "__DATA",
                0x100008C80,
                0x8,
                0x8C80,
                3,
                0,
                0,
                0x10000000,
            ),
            (
                "__objc_superrefs",
                "__DATA",
                0x100008C88,
                0x8,
                0x8C88,
                3,
                0,
                0,
                0x10000000,
            ),
            ("__objc_ivar", "__DATA", 0x100008C90, 0x4, 0x8C90, 2, 0, 0, 0),
            ("__objc_data", "__DATA", 0x100008C98, 0xA0, 0x8C98, 3, 0, 0, 0),
            ("__data", "__DATA", 0x100008D38, 0xB0, 0x8D38, 3, 0, 0, 0),
        ],
    }

    expected_memory = {
        # Memory-address=>byte
        0x100000000: 0xCF,
        0x1000067DC: 0xFD,
        0x100006C0C: 0x1F,
        0x100006C84: 0x31,
        0x100006D14: 0x76,
        0x1000076F3: 0x56,
        0x10000772F: 0x76,
        0x100007F2B: 0x25,
        0x100007FAC: 0x01,
        # TODO: Test data sections, requires proper parsing and handling of these sections
    }

    assert len(expected_segments) == len(macho.segments)
    for segment_tuple in expected_segments:
        segname, vaddr, vsize, foff, fsize, nsect, flags = segment_tuple
        seg = macho[segname]
        assert seg is not None
        assert segname == seg.segname
        assert vaddr == seg.vaddr
        assert vsize == seg.memsize
        assert foff == seg.offset
        assert fsize == seg.filesize
        assert nsect == seg.nsect
        assert flags == seg.flags

    for k in expected_sections:
        seg = macho[k]
        assert len(expected_sections[k]) == len(seg.sections)
        for segment_tuple in expected_sections[k]:
            (
                secname,
                segname,
                vaddr,
                vsize,
                foff,
                align,
                reloff,
                nreloc,
                flags,
            ) = segment_tuple
            sec = seg[secname]
            # print secname
            assert sec is not None
            assert secname == sec.sectname
            assert segname == sec.segname
            assert vaddr == sec.vaddr
            assert vsize == sec.memsize
            assert foff == sec.offset
            assert vsize == sec.filesize
            assert align == sec.align
            assert reloff == sec.reloff
            assert nreloc == sec.nreloc
            assert flags == sec.flags

    # Test memory layout - just a crude approximation by taking samples but sufficient for now
    for k, v in expected_memory.items():
        # print hex(k)
        assert v == ld.memory[k]


def test_find_object_containing():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)

    entry = ld.main_object.entry
    assert ld.find_object_containing(entry) is ld.main_object


def test_addresses():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)

    assert ld.main_object.min_addr == 0x100000000
    # The entry point is at
    assert ld.main_object.entry == 0x100000DE0
    assert ld.main_object.max_addr == 0x100002FFF


def test_find_section_containing():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)

    section = ld.find_section_containing(ld.main_object.entry)
    assert section is not None
    assert section.name == "__text"


def test_find_region_containing():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)

    region = ld.main_object.sections.find_region_containing(ld.main_object.entry)
    assert isinstance(region, MachOSection)
    assert region.name == "__text"


def test_describe_addr():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)

    assert ld.describe_addr(ld.main_object.entry) == "_main+0x0 in fauxware.macho (0x100000de0)"


def test_zerofill_sections():
    machofile = os.path.join(TEST_BASE, "tests", "aarch64", "dyld_ios15.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)
    macho = ld.main_object
    assert isinstance(macho, cle.MachO)

    bss = macho.sections_map["__DATA,__bss"]
    assert isinstance(bss, MachOSection)
    assert bss.type == SectionType.S_ZEROFILL
    assert bss.only_contains_uninitialized_data

    assert not macho.sections_map["__TEXT,__text"].only_contains_uninitialized_data
    assert not macho.sections_map["__DATA,__data"].only_contains_uninitialized_data
    assert {s.name for s in macho.sections if s.only_contains_uninitialized_data} == {"__bss"}


def test_instruction_sections():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)
    macho = ld.main_object
    assert isinstance(macho, cle.MachO)

    # ld64 marks the whole of __TEXT executable, so the segment holding the code also holds the string literals
    # and the unwind table and cannot tell them apart.
    text = macho["__TEXT"]
    assert text is not None
    assert text.is_executable
    assert {s.sectname for s in text.sections} == {
        "__text",
        "__stubs",
        "__stub_helper",
        "__cstring",
        "__unwind_info",
    }

    assert {name for name, section in macho.sections_map.items() if section.is_executable} == {
        "__TEXT,__text",
        "__TEXT,__stubs",
        "__TEXT,__stub_helper",
    }
    assert macho.sections_map["__TEXT,__text"].attributes & SectionAttributes.S_ATTR_PURE_INSTRUCTIONS
    assert macho.sections_map["__TEXT,__cstring"].attributes == 0


def test_find_symbol():
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)

    # Test finding a user defined symbol
    sym = ld.find_symbol("_main")
    assert sym is not None
    assert sym.name == "_main"
    assert sym.rebased_addr == 0x100000DE0

    # Test finding an imported symbol
    sym = ld.find_symbol("_printf")
    assert sym is not None
    assert sym.name == "_printf"
    assert sym.rebased_addr == 0x100100028


def _find_segment_command(image: bytes, segname: bytes) -> int:
    """
    Offset of the LC_SEGMENT_64 command for the given segment
    """
    ncmds = struct.unpack_from("<I", image, 16)[0]
    offset = 32
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<2I", image, offset)
        if (
            cmd == LoadCommands.LC_SEGMENT_64
            and struct.unpack_from("<16s", image, offset + 8)[0].rstrip(b"\0") == segname
        ):
            return offset
        offset += cmdsize
    raise AssertionError(f"No {segname!r} segment")


def _insert_segment_command(
    image: bytes, offset: int, segname: bytes, vmaddr: int, vmsize: int, fileoff: int, filesize: int
) -> bytes:
    """
    Splice a sectionless LC_SEGMENT_64 into a 64 bit Mach-O image at the given load command offset. The command takes
    the place of padding that follows the load commands, so the image keeps its length and every file offset in it
    stays valid.
    """
    ncmds, sizeofcmds = struct.unpack_from("<2I", image, 16)
    command = struct.pack(
        SEGMENT_COMMAND_64,
        LoadCommands.LC_SEGMENT_64,
        SEGMENT_COMMAND_64_SIZE,
        segname,
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        7,  # maxprot: rwx
        1,  # initprot: r
        0,  # nsects
        0,  # flags
    )
    padding = 32 + sizeofcmds
    assert set(image[padding : padding + SEGMENT_COMMAND_64_SIZE]) == {0}, "not enough padding to hold a segment"

    patched = bytearray(image)
    patched[offset:offset] = command
    del patched[padding + SEGMENT_COMMAND_64_SIZE : padding + 2 * SEGMENT_COMMAND_64_SIZE]
    struct.pack_into("<2I", patched, 16, ncmds + 1, sizeofcmds + SEGMENT_COMMAND_64_SIZE)
    return bytes(patched)


def test_zero_vmsize_segment():
    """
    A segment with vmsize 0 occupies no memory, so the linker gives the segment that follows it the same vmaddr. This
    is how debug info that stays in the executable is emitted: __DWARF has vmsize 0 and the full debug info as its file
    content, directly in front of __LINKEDIT. Backing such a segment with its file content maps it over __LINKEDIT.
    """
    with open(os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho"), "rb") as fp:
        image = fp.read()

    patched = _insert_segment_command(
        image,
        _find_segment_command(image, b"__LINKEDIT"),
        b"__DWARF",
        vmaddr=0x100002000,  # the address of __LINKEDIT
        vmsize=0,
        fileoff=0xCC0,  # the file range of __text, standing in for debug info
        filesize=0x340,
    )

    ld = cle.Loader(BytesIO(patched), auto_load_libs=False, main_opts={"backend": "mach-o"})
    assert isinstance(ld.main_object, cle.MachO)
    macho: MachO = ld.main_object
    assert [seg.segname for seg in macho.segments] == ["__PAGEZERO", "__TEXT", "__DATA", "__DWARF", "__LINKEDIT"]

    # __DWARF contributed nothing, so __LINKEDIT is intact and the backers are the ones the unpatched binary has
    backers = [(start, len(backer)) for start, backer in macho.memory.backers()]
    assert backers == [(0, 0x1000), (0x1000, 0x1000), (0x2000, 0x1000)]
    assert ld.memory.load(0x100002000, 16) == image[0x2000:0x2010]


def test_filesize_larger_than_vmsize():
    """
    A segment maps vmsize bytes, so anything its file range holds beyond that is not part of the mapping.
    """
    with open(os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho"), "rb") as fp:
        image = fp.read()

    patched = _insert_segment_command(
        image,
        _find_segment_command(image, b"__LINKEDIT"),
        b"__OVERSIZED",
        vmaddr=0x100003000,  # past the end of the binary
        vmsize=0x1000,
        fileoff=0,
        filesize=0x2000,
    )

    ld = cle.Loader(BytesIO(patched), auto_load_libs=False, main_opts={"backend": "mach-o"})
    assert isinstance(ld.main_object, cle.MachO)
    macho: MachO = ld.main_object
    assert dict(macho.memory.backers())[0x3000] == patched[:0x1000]
    assert macho.max_addr == 0x100003FFF


def test_non_macho_magic_is_reported():
    """
    A file that is not Mach-O at all, pushed through the Mach-O backend, must say so. The backend used to
    reject it with a CLECompatibilityError carrying no message, which left nothing in a log to tell that
    rejection apart from every other reason the backend can refuse a file.
    """
    elffile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware")
    with pytest.raises(cle.CLECompatibilityError) as excinfo:
        cle.Loader(elffile, auto_load_libs=False, main_opts={"backend": "mach-o"})

    # The magic that was found, and the four the backend accepts, so the message alone identifies the file
    # and the check that rejected it.
    message = str(excinfo.value)
    assert "0x464c457f" in message
    for magic in (MachO.MH_MAGIC, MachO.MH_CIGAM, MachO.MH_MAGIC_64, MachO.MH_CIGAM_64):
        assert f"{magic:#010x}" in message


def _copy_with_header_field(source, destination, offset, value):
    """Copy a little-endian Mach-O file, replacing one 32-bit field of its mach header"""
    with open(source, "rb") as f:
        data = bytearray(f.read())
    struct.pack_into("<I", data, offset, value)
    with open(destination, "wb") as f:
        f.write(data)
    return destination


def _copy_with_executable_library_ordinal(source, destination):
    """Copy a Mach-O file, re-encoding every dynamic lookup import as one bound to the main executable

    That is how the linker encodes the undefined symbols of a dlopen-ed bundle, which resolve against
    whichever executable loaded it. The ordinal is recorded both in the symbol table and in the chained
    fixup imports, and the two have to agree for a symbol to be matched up again while loading.
    """
    ld = cle.Loader(source, auto_load_libs=False)
    assert isinstance(ld.main_object, MachO)
    macho: MachO = ld.main_object
    assert macho.symtab_offset is not None and macho.symtab_nsyms is not None
    assert macho._dyld_chained_fixups_offset is not None

    with open(source, "rb") as f:
        data = bytearray(f.read())

    nlist_size = 16 if macho.arch.bits == 64 else 12
    for i in range(macho.symtab_nsyms):
        entry = macho.symtab_offset + i * nlist_size
        n_strx, n_type, n_sect, n_desc = struct.unpack_from(NLIST_PREFIX, data, entry)
        if n_type & N_STAB or not n_type & N_EXT or n_type & 0x0E != SYMBOL_TYPE_UNDEF:
            continue
        if (n_desc >> 8) & 0xFF == LIBRARY_ORDINAL_DYN_LOOKUP:
            n_desc = (n_desc & 0xFF) | (LIBRARY_ORDINAL_EXECUTABLE << 8)
            struct.pack_into(NLIST_PREFIX, data, entry, n_strx, n_type, n_sect, n_desc)

    header = dyld_chained_fixups_header.from_buffer(data, macho._dyld_chained_fixups_offset)
    import_struct = DyldImportStruct.get_struct(header.imports_format)
    imports_offset = macho._dyld_chained_fixups_offset + header.imports_offset
    for i in range(header.imports_count):
        imported = import_struct.from_buffer(data, imports_offset + i * ctypes.sizeof(import_struct))
        if imported.lib_ordinal == LIBRARY_ORDINAL_DYN_LOOKUP:
            imported.lib_ordinal = LIBRARY_ORDINAL_EXECUTABLE

    with open(destination, "wb") as f:
        f.write(data)
    return destination


def test_kext():
    """A kernel extension is an ordinary linked image whose segments are relative to 0, like a dylib's"""
    machofile = os.path.join(TEST_BASE, "tests", "aarch64", "IPwnKit.macho.kext")
    ld = cle.Loader(machofile, auto_load_libs=False)
    assert isinstance(ld.main_object, MachO)
    macho: MachO = ld.main_object

    assert macho.filetype == MachoFiletype.MH_KEXT_BUNDLE
    assert macho.pic
    assert [seg.segname for seg in macho.segments] == [
        "__TEXT",
        "__TEXT_EXEC",
        "__DATA",
        "__DATA_CONST",
        "__LINKEDIT",
    ]
    assert (macho.min_addr, macho.max_addr) == (0x0, 0x23FFF)
    assert len(macho.symbols) == 846


def test_bundle():
    """A dlopen-ed plugin bundle is laid out just like a dylib, and only its filetype field differs"""
    machofile = os.path.join(
        TEST_BASE,
        "tests",
        "aarch64",
        "macho_lib_loading",
        "FrameWorkApp.app_14",
        "Frameworks",
        "dynamicLibrary.framework",
        "dynamicLibrary",
    )
    dylib_ld = cle.Loader(machofile, auto_load_libs=False)
    assert isinstance(dylib_ld.main_object, MachO)
    dylib: MachO = dylib_ld.main_object

    with tempfile.TemporaryDirectory() as tmpdir:
        bundle_file = _copy_with_header_field(
            machofile, os.path.join(tmpdir, "dynamicLibrary.bundle"), FILETYPE_OFFSET, MachoFiletype.MH_BUNDLE
        )
        bundle_ld = cle.Loader(bundle_file, auto_load_libs=False)
        assert isinstance(bundle_ld.main_object, MachO)
        bundle: MachO = bundle_ld.main_object

    assert bundle.filetype == MachoFiletype.MH_BUNDLE
    assert bundle.pic
    assert [seg.segname for seg in bundle.segments] == [seg.segname for seg in dylib.segments]
    assert (bundle.min_addr, bundle.max_addr) == (dylib.min_addr, dylib.max_addr)


def test_executable_library_ordinal():
    """Library ordinal 255 names the executable that loaded the image, not one of its imported libraries"""
    machofile = os.path.join(TEST_BASE, "tests", "aarch64", "IPwnKit.macho.kext")

    with tempfile.TemporaryDirectory() as tmpdir:
        patched = _copy_with_executable_library_ordinal(machofile, os.path.join(tmpdir, "IPwnKit.macho.kext"))
        ld = cle.Loader(patched, auto_load_libs=False)
        assert isinstance(ld.main_object, MachO)
        macho: MachO = ld.main_object

    imports = [sym for sym in macho.symbols if sym.library_ordinal == LIBRARY_ORDINAL_EXECUTABLE]
    assert imports
    assert all(sym.library_name is None for sym in imports)


def test_non_pie_executable_is_not_pic():
    """Position independence comes from the MH_PIE flag, not from a bitwise test against a filetype ordinal"""
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    stock_ld = cle.Loader(machofile, auto_load_libs=False)
    assert isinstance(stock_ld.main_object, MachO)
    stock: MachO = stock_ld.main_object
    assert stock.flags is not None and stock.flags & MH_flags.MH_PIE
    assert stock.pic

    with tempfile.TemporaryDirectory() as tmpdir:
        non_pie = _copy_with_header_field(
            machofile, os.path.join(tmpdir, "fauxware.nonpie"), FLAGS_OFFSET, stock.flags & ~MH_flags.MH_PIE
        )

        ld = cle.Loader(non_pie, auto_load_libs=False)
        assert isinstance(ld.main_object, MachO)
        macho: MachO = ld.main_object
        assert macho.filetype == MachoFiletype.MH_EXECUTE
        assert not macho.pic
        assert macho.linked_base == macho.mapped_base == 0x100000000

        # force_rebase is a loader option, so it still decides position independence on its own
        forced_ld = cle.Loader(non_pie, auto_load_libs=False, main_opts={"force_rebase": True})
        assert isinstance(forced_ld.main_object, MachO)
        assert forced_ld.main_object.pic


def test_dsym_is_rejected():
    """A dSYM companion holds debug information only, so the refusal says that instead of asking for a report"""
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    with tempfile.TemporaryDirectory() as tmpdir:
        dsym = _copy_with_header_field(
            machofile, os.path.join(tmpdir, "fauxware.dSYM"), FILETYPE_OFFSET, MachoFiletype.MH_DSYM
        )
        with pytest.raises(CLECompatibilityError, match="debug information"):
            cle.Loader(dsym, auto_load_libs=False)


def test_unsupported_filetype_is_named():
    """A filetype this backend cannot map yet is refused by name, not as a bare number"""
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    with tempfile.TemporaryDirectory() as tmpdir:
        obj = _copy_with_header_field(
            machofile, os.path.join(tmpdir, "fauxware.o"), FILETYPE_OFFSET, MachoFiletype.MH_OBJECT
        )
        with pytest.raises(CLECompatibilityError, match="MH_OBJECT"):
            cle.Loader(obj, auto_load_libs=False)


def test_unknown_filetype():
    """A filetype outside the enum is a damaged header, which is this backend's problem to report"""
    machofile = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.macho")
    with tempfile.TemporaryDirectory() as tmpdir:
        damaged = _copy_with_header_field(machofile, os.path.join(tmpdir, "fauxware.damaged"), FILETYPE_OFFSET, 99)
        with pytest.raises(CLECompatibilityError, match="Unknown Mach-O file type: 0x63"):
            cle.Loader(damaged, auto_load_libs=False)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_dummy()
    test_find_object_containing()
    test_addresses()
    test_find_section_containing()
    test_find_region_containing()
    test_describe_addr()
    test_find_symbol()
    test_zerofill_sections()
    test_instruction_sections()
    test_zero_vmsize_segment()
    test_filesize_larger_than_vmsize()
    test_kext()
    test_bundle()
    test_executable_library_ordinal()
    test_non_pie_executable_is_not_pic()
    test_dsym_is_rejected()
    test_unsupported_filetype_is_named()
    test_unknown_filetype()
