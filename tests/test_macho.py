#!/usr/bin/env python
from __future__ import annotations

import logging
import os

import cle
from cle import MachO
from cle.backends.macho.section import MachOSection

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


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
        (segname, vaddr, vsize, foff, fsize, nsect, flags) = segment_tuple
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_dummy()
    test_find_object_containing()
    test_addresses()
    test_find_section_containing()
    test_find_region_containing()
    test_describe_addr()
