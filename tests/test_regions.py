
import os

import nose

import cle
from cle.backends import Section, Segment
from cle.address_translator import AT


TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..','..','binaries','tests'))


groundtruth = {
    ('x86_64', 'allcmps'): {
        'sections': [
                        Section('', 0x0, 0x0, 0x0),
                        Section('.interp', 0x238, 0x400238, 0x1c),
                        Section('.note.ABI-tag', 0x254, 0x400254, 0x20),
                        Section('.note.gnu.build-id', 0x274, 0x400274, 0x24),
                        Section('.gnu.hash', 0x298, 0x400298, 0x1c),
                        Section('.dynsym', 0x2b8, 0x4002b8, 0x48),
                        Section('.dynstr', 0x300, 0x400300, 0x38),
                        Section('.gnu.version', 0x338, 0x400338, 0x6),
                        Section('.gnu.version_r', 0x340, 0x400340, 0x20),
                        Section('.rela.dyn', 0x360, 0x400360, 0x18),
                        Section('.rela.plt', 0x378, 0x400378, 0x30),
                        Section('.init', 0x3a8, 0x4003a8, 0x1a),
                        Section('.plt', 0x3d0, 0x4003d0, 0x30),
                        Section('.text', 0x400, 0x400400, 0x2c4),
                        Section('.fini', 0x6c4, 0x4006c4, 0x9),
                        Section('.rodata', 0x6d0, 0x4006d0, 0x4),
                        Section('.eh_frame_hdr', 0x6d4, 0x4006d4, 0x3c),
                        Section('.eh_frame', 0x710, 0x400710, 0xf4),
                        Section('.init_array', 0xe10, 0x600e10, 0x8),
                        Section('.fini_array', 0xe18, 0x600e18, 0x8),
                        Section('.jcr', 0xe20, 0x600e20, 0x8),
                        Section('.dynamic', 0xe28, 0x600e28, 0x1d0),
                        Section('.got', 0xff8, 0x600ff8, 0x8),
                        Section('.got.plt', 0x1000, 0x601000, 0x28),
                        Section('.data', 0x1028, 0x601028, 0x10),
                        Section('.bss', 0x1038, 0x601038, 0x8),
                        Section('.comment', 0x1038, 0x0, 0x2a),
                        Section('.shstrtab', 0x1062, 0x0, 0x108),
                        Section('.symtab', 0x18f0, 0x0, 0x630),
                        Section('.strtab', 0x1f20, 0x0, 0x232),
        ],
        'segments': [
            Segment(0, 0x400000, 0x804, 0x804),
            Segment(0xe10, 0x600e10, 0x228, 0x230),
        ],
    }
}


def run_sections(arch, filename, sections):

    binary_path = os.path.join(TESTS_BASE, arch, filename)

    ld = cle.Loader(binary_path, auto_load_libs=False)

    nose.tools.assert_equal(len(ld.main_object.sections), len(sections))
    for i, section in enumerate(ld.main_object.sections):
        nose.tools.assert_equal(section.name, sections[i].name)
        nose.tools.assert_equal(section.offset, sections[i].offset)
        nose.tools.assert_equal(AT.from_mva(section.vaddr, ld.main_object).to_lva(), sections[i].vaddr)
        nose.tools.assert_equal(section.memsize, sections[i].memsize)

    # address lookups
    nose.tools.assert_is_none(ld.main_object.sections.find_region_containing(-1))

    # skip all sections that are not mapped into memory
    mapped_sections = [ section for section in sections if section.vaddr != 0 ]

    for section in mapped_sections:
        nose.tools.assert_equal(ld.main_object.find_section_containing(section.vaddr).name, section.name)
        nose.tools.assert_equal(ld.main_object.sections.find_region_containing(section.vaddr).name, section.name)
        if section.memsize > 0:
            nose.tools.assert_equal(ld.main_object.find_section_containing(section.vaddr + 1).name, section.name)
            nose.tools.assert_equal(ld.main_object.sections.find_region_containing(section.vaddr + 1).name, section.name)
            nose.tools.assert_equal(ld.main_object.find_section_containing(section.vaddr + section.memsize - 1).name,
                                    section.name)
            nose.tools.assert_equal(
                ld.main_object.sections.find_region_containing(section.vaddr + section.memsize - 1).name, section.name)

    for i in xrange(len(mapped_sections) - 1):
        sec_a, sec_b = mapped_sections[i], mapped_sections[i + 1]
        if sec_a.vaddr + sec_a.memsize < sec_b.vaddr:
            # there is a gap between sec_a and sec_b
            for j in xrange(min(sec_b.vaddr - (sec_a.vaddr + sec_a.memsize), 20)):
                a = sec_a.vaddr + sec_a.memsize + j
                nose.tools.assert_is_none(ld.main_object.find_section_containing(a))
                nose.tools.assert_is_none(ld.main_object.sections.find_region_containing(a))

    nose.tools.assert_is_none(ld.main_object.find_section_containing(0xffffffff), None)

def run_segments(arch, filename, segments):

    binary_path = os.path.join(TESTS_BASE, arch, filename)

    ld = cle.Loader(binary_path, auto_load_libs=False)

    nose.tools.assert_equal(len(ld.main_object.segments), len(segments))
    for i, segment in enumerate(ld.main_object.segments):
        nose.tools.assert_equal(segment.offset, segments[i].offset)
        nose.tools.assert_equal(segment.vaddr, segments[i].vaddr)
        nose.tools.assert_equal(segment.memsize, segments[i].memsize)
        nose.tools.assert_equal(segment.filesize, segments[i].filesize)

    # address lookups
    nose.tools.assert_is_none(ld.main_object.segments.find_region_containing(-1))

    # skip all segments that are not mapped into memory
    mapped_segments = [ segment for segment in segments if segment.vaddr != 0 ]

    for segment in mapped_segments:
        nose.tools.assert_equal(ld.main_object.find_segment_containing(segment.vaddr).vaddr, segment.vaddr)
        nose.tools.assert_equal(ld.main_object.segments.find_region_containing(segment.vaddr).vaddr, segment.vaddr)
        if segment.memsize > 0:
            nose.tools.assert_equal(ld.main_object.find_segment_containing(segment.vaddr + 1).vaddr, segment.vaddr)
            nose.tools.assert_equal(ld.main_object.segments.find_region_containing(segment.vaddr + 1).vaddr, segment.vaddr)
            nose.tools.assert_equal(ld.main_object.find_segment_containing(segment.vaddr + segment.memsize - 1).vaddr,
                                    segment.vaddr)
            nose.tools.assert_equal(
                ld.main_object.segments.find_region_containing(segment.vaddr + segment.memsize - 1).vaddr, segment.vaddr)

    for i in xrange(len(mapped_segments) - 1):
        seg_a, seg_b = mapped_segments[i], mapped_segments[i + 1]
        if seg_a.vaddr + seg_a.memsize < seg_b.vaddr:
            # there is a gap between seg_a and seg_b
            for j in xrange(min(seg_b.vaddr - (seg_a.vaddr + seg_a.memsize), 20)):
                a = seg_a.vaddr + seg_a.memsize + j
                nose.tools.assert_is_none(ld.main_object.find_segment_containing(a))
                nose.tools.assert_is_none(ld.main_object.segments.find_region_containing(a))

    nose.tools.assert_is_none(ld.main_object.find_segment_containing(0xffffffff), None)


def test_all():

    for (arch, filename), data in groundtruth.iteritems():
        yield run_sections, arch, filename, data['sections']
        yield run_segments, arch, filename, data['segments']


if __name__ == "__main__":
    test_all()
