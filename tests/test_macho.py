#!/usr/bin/env python

import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))

def test_fauxware():
    machofile = os.path.join(TEST_BASE, 'tests', 'x86_64', 'fauxware.macho')
    ld = cle.Loader(machofile, auto_load_libs=False)
    nose.tools.assert_true(isinstance(ld.main_object,cle.MachO))
    nose.tools.assert_equal(ld.main_object.os, 'macos')
    nose.tools.assert_equal(ld.main_object.entry, 0x100000de0)
    nose.tools.assert_equal(sorted(list(ld.main_object.exports_by_name))[-1], '_sneaky')


# Contributed September 2019 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).
def test_dummy():
    """All-in-one testcase exercising all features in combination for 64 bit binaries"""
    # TODO: Updated with new features

    machofile = os.path.join(TEST_BASE, 'tests', 'armhf', 'dummy.macho')
    ld = cle.Loader(machofile, auto_load_libs=False)
    macho = ld.main_object
    expected_segments = [
        # segname, vaddr,vsize,foff,fsize,nsect,flags,
        ("__PAGEZERO",  0x0,        0x100000000,0,      0,      0,  0),
        ("__TEXT",      0x100000000,0x8000,     0,      0x8000, 8,  0),
        ("__DATA",      0x100008000,0x4000,     0x8000, 0x4000, 13, 0),
        ("__LINKEDIT",  0x10000C000,0x4000,     0xC000, 0x3ba0, 0,  0)
    ]

    expected_sections = {
        # segname=> (secname,segname,vaddr,vsize,foff,align,reloff,nreloc,flags)
        "__TEXT": [
            ("__text", "__TEXT", 0x1000067dc, 0x430, 0x67dc, 0x2, 0, 0, 0x80000400),
            ("__stubs", "__TEXT", 0x100006c0c, 0x78, 0x6c0c, 0x1, 0, 0, 0x80000408),
            ("__stub_helper", "__TEXT", 0x100006c84, 0x90, 0x6c84, 0x2, 0, 0, 0x80000400),
            ("__objc_methname", "__TEXT", 0x100006d14, 0x9df, 0x6d14, 0, 0, 0, 0x2),
            ("__objc_classname", "__TEXT", 0x1000076f3, 0x3c, 0x76f3, 0, 0, 0, 0x2),
            ("__objc_methtype", "__TEXT", 0x10000772F, 0x7fc, 0x772f, 0, 0, 0, 0x2),
            ("__cstring", "__TEXT", 0x100007f2b, 0x7f, 0x7f2b, 0, 0, 0, 0x2),
            ("__unwind_info", "__TEXT", 0x100007fac, 0x54, 0x7fac, 0x2, 0, 0, 0)
        ],
        "__DATA": [
            ("__got", "__DATA", 0x100008000, 0x10, 0x8000, 3, 0, 0, 0x6),
            ("__la_symbol_ptr", "__DATA", 0x100008010, 0x50, 0x8010, 3, 0, 0, 0x7),
            ("__cfstring", "__DATA", 0x100008060, 0x20, 0x8060, 3, 0, 0, 0),
            ("__objc_classlist", "__DATA", 0x100008080, 0x10, 0x8080, 3, 0, 0, 0x10000000),
            ("__objc_protolist", "__DATA", 0x100008090, 0x10, 0x8090, 3, 0, 0, 0),
            ("__objc_imageinfo", "__DATA", 0x1000080a0, 0x8, 0x80a0, 2, 0, 0, 0),
            ("__objc_const", "__DATA", 0x1000080a8, 0xbc0, 0x80a8, 3, 0, 0, 0),
            ("__objc_selrefs", "__DATA", 0x100008c68, 0x18, 0x8c68, 3, 0, 0, 0x10000005),
            ("__objc_classrefs", "__DATA", 0x100008c80, 0x8, 0x8c80, 3, 0, 0, 0x10000000),
            ("__objc_superrefs", "__DATA", 0x100008c88, 0x8, 0x8c88, 3, 0, 0, 0x10000000),
            ("__objc_ivar", "__DATA", 0x100008c90, 0x4, 0x8c90, 2, 0, 0, 0),
            ("__objc_data", "__DATA", 0x100008c98, 0xa0, 0x8c98, 3, 0, 0, 0),
            ("__data", "__DATA", 0x100008d38, 0xb0, 0x8d38, 3, 0, 0, 0)
        ]
    }

    expected_memory = {
        # Memory-address=>byte
        0x100000000: 0xcf,
        0x1000067dc: 0xfd,
        0x100006c0c: 0x1f,
        0x100006c84: 0x31,
        0x100006d14: 0x76,
        0x1000076f3: 0x56,
        0x10000772F: 0x76,
        0x100007f2b: 0x25,
        0x100007fac: 0x01,
        # TODO: Test data sections, requires proper parsing and handling of these sections
    }

    nose.tools.assert_equal(len(expected_segments), len(macho.segments))
    for segment_tuple in expected_segments:
        (segname, vaddr, vsize, foff, fsize, nsect, flags) = segment_tuple
        seg = macho[segname]
        nose.tools.assert_is_not_none(seg)
        nose.tools.assert_equal(segname, seg.segname)
        nose.tools.assert_equal(vaddr, seg.vaddr)
        nose.tools.assert_equal(vsize, seg.memsize)
        nose.tools.assert_equal(foff, seg.offset)
        nose.tools.assert_equal(fsize, seg.filesize)
        nose.tools.assert_equal(nsect, seg.nsect)
        nose.tools.assert_equal(flags, seg.flags)

    for k in expected_sections:
        seg = macho[k]
        nose.tools.assert_equal(len(expected_sections[k]), len(seg.sections))
        for segment_tuple in expected_sections[k]:
            (secname, segname, vaddr, vsize, foff, align, reloff, nreloc, flags) = segment_tuple
            sec = seg[secname]
            # print secname
            nose.tools.assert_is_not_none(sec)
            nose.tools.assert_equal(secname, sec.sectname)
            nose.tools.assert_equal(segname, sec.segname)
            nose.tools.assert_equal(vaddr, sec.vaddr)
            nose.tools.assert_equal(vsize, sec.memsize)
            nose.tools.assert_equal(foff, sec.offset)
            nose.tools.assert_equal(vsize, sec.filesize)
            nose.tools.assert_equal(align, sec.align)
            nose.tools.assert_equal(reloff, sec.reloff)
            nose.tools.assert_equal(nreloc, sec.nreloc)
            nose.tools.assert_equal(flags, sec.flags)

    # Test memory layout - just a crude approximation by taking samples but sufficient for now
    for k, v in expected_memory.items():
        # print hex(k)
        nose.tools.assert_equal(v, macho.memory[k])

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_fauxware()
    test_dummy()
