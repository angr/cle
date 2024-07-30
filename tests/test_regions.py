from __future__ import annotations

import os
import unittest

import cle
from cle.address_translator import AT
from cle.backends import Section, Segment

TESTS_BASE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


groundtruth = {
    ("x86_64", "allcmps"): {
        "sections": [
            Section("", 0x0, 0x0, 0x0),
            Section(".interp", 0x238, 0x400238, 0x1C),
            Section(".note.ABI-tag", 0x254, 0x400254, 0x20),
            Section(".note.gnu.build-id", 0x274, 0x400274, 0x24),
            Section(".gnu.hash", 0x298, 0x400298, 0x1C),
            Section(".dynsym", 0x2B8, 0x4002B8, 0x48),
            Section(".dynstr", 0x300, 0x400300, 0x38),
            Section(".gnu.version", 0x338, 0x400338, 0x6),
            Section(".gnu.version_r", 0x340, 0x400340, 0x20),
            Section(".rela.dyn", 0x360, 0x400360, 0x18),
            Section(".rela.plt", 0x378, 0x400378, 0x30),
            Section(".init", 0x3A8, 0x4003A8, 0x1A),
            Section(".plt", 0x3D0, 0x4003D0, 0x30),
            Section(".text", 0x400, 0x400400, 0x2C4),
            Section(".fini", 0x6C4, 0x4006C4, 0x9),
            Section(".rodata", 0x6D0, 0x4006D0, 0x4),
            Section(".eh_frame_hdr", 0x6D4, 0x4006D4, 0x3C),
            Section(".eh_frame", 0x710, 0x400710, 0xF4),
            Section(".init_array", 0xE10, 0x600E10, 0x8),
            Section(".fini_array", 0xE18, 0x600E18, 0x8),
            Section(".jcr", 0xE20, 0x600E20, 0x8),
            Section(".dynamic", 0xE28, 0x600E28, 0x1D0),
            Section(".got", 0xFF8, 0x600FF8, 0x8),
            Section(".got.plt", 0x1000, 0x601000, 0x28),
            Section(".data", 0x1028, 0x601028, 0x10),
            Section(".bss", 0x1038, 0x601038, 0x8),
            Section(".comment", 0x1038, 0x0, 0x2A),
            Section(".shstrtab", 0x1062, 0x0, 0x108),
            Section(".symtab", 0x18F0, 0x0, 0x630),
            Section(".strtab", 0x1F20, 0x0, 0x232),
        ],
        "segments": [
            Segment(0, 0x400000, 0x804, 0x804),
            Segment(0xE10, 0x600E10, 0x1F0, 0x1F0),
            Segment(0x1000, 0x601000, 0x38, 0x40),
        ],
    }
}


class TestRunSections(unittest.TestCase):
    def _run_sections(self, arch, filename, sections):
        binary_path = os.path.join(TESTS_BASE, arch, filename)

        ld = cle.Loader(binary_path, auto_load_libs=False)

        self.assertEqual(len(ld.main_object.sections), len(sections))
        for i, section in enumerate(ld.main_object.sections):
            self.assertEqual(section.name, sections[i].name)
            self.assertEqual(section.offset, sections[i].offset)
            self.assertEqual(AT.from_mva(section.vaddr, ld.main_object).to_lva(), sections[i].vaddr)
            self.assertEqual(section.memsize, sections[i].memsize)

        # address lookups
        self.assertIsNone(ld.main_object.sections.find_region_containing(-1))

        # skip all sections that are not mapped into memory
        mapped_sections = [section for section in sections if section.vaddr != 0]

        for section in mapped_sections:
            self.assertEqual(ld.main_object.find_section_containing(section.vaddr).name, section.name)
            self.assertEqual(
                ld.main_object.sections.find_region_containing(section.vaddr).name,
                section.name,
            )
            if section.memsize > 0:
                self.assertEqual(
                    ld.main_object.find_section_containing(section.vaddr + 1).name,
                    section.name,
                )
                self.assertEqual(
                    ld.main_object.sections.find_region_containing(section.vaddr + 1).name,
                    section.name,
                )
                self.assertEqual(
                    ld.main_object.find_section_containing(section.vaddr + section.memsize - 1).name,
                    section.name,
                )
                self.assertEqual(
                    ld.main_object.sections.find_region_containing(section.vaddr + section.memsize - 1).name,
                    section.name,
                )

        for i in range(len(mapped_sections) - 1):
            sec_a, sec_b = mapped_sections[i], mapped_sections[i + 1]
            if sec_a.vaddr + sec_a.memsize < sec_b.vaddr:
                # there is a gap between sec_a and sec_b
                for j in range(min(sec_b.vaddr - (sec_a.vaddr + sec_a.memsize), 20)):
                    a = sec_a.vaddr + sec_a.memsize + j
                    self.assertIsNone(ld.main_object.find_section_containing(a))
                    self.assertIsNone(ld.main_object.sections.find_region_containing(a))

        self.assertIsNone(ld.main_object.find_section_containing(0xFFFFFFFF), None)

    def _run_segments(self, arch, filename, segments):
        binary_path = os.path.join(TESTS_BASE, arch, filename)

        ld = cle.Loader(binary_path, auto_load_libs=False)

        self.assertEqual(len(ld.main_object.segments), len(segments))
        for i, segment in enumerate(ld.main_object.segments):
            self.assertEqual(segment.offset, segments[i].offset)
            self.assertEqual(segment.vaddr, segments[i].vaddr)
            self.assertEqual(segment.memsize, segments[i].memsize)
            self.assertEqual(segment.filesize, segments[i].filesize)

        # address lookups
        self.assertIsNone(ld.main_object.segments.find_region_containing(-1))

        # skip all segments that are not mapped into memory
        mapped_segments = [segment for segment in segments if segment.vaddr != 0]

        for segment in mapped_segments:
            self.assertEqual(
                ld.main_object.find_segment_containing(segment.vaddr).vaddr,
                segment.vaddr,
            )
            self.assertEqual(
                ld.main_object.segments.find_region_containing(segment.vaddr).vaddr,
                segment.vaddr,
            )
            if segment.memsize > 0:
                self.assertEqual(
                    ld.main_object.find_segment_containing(segment.vaddr + 1).vaddr,
                    segment.vaddr,
                )
                self.assertEqual(
                    ld.main_object.segments.find_region_containing(segment.vaddr + 1).vaddr,
                    segment.vaddr,
                )
                self.assertEqual(
                    ld.main_object.find_segment_containing(segment.vaddr + segment.memsize - 1).vaddr,
                    segment.vaddr,
                )
                self.assertEqual(
                    ld.main_object.segments.find_region_containing(segment.vaddr + segment.memsize - 1).vaddr,
                    segment.vaddr,
                )

        for i in range(len(mapped_segments) - 1):
            seg_a, seg_b = mapped_segments[i], mapped_segments[i + 1]
            if seg_a.vaddr + seg_a.memsize < seg_b.vaddr:
                # there is a gap between seg_a and seg_b
                for j in range(min(seg_b.vaddr - (seg_a.vaddr + seg_a.memsize), 20)):
                    a = seg_a.vaddr + seg_a.memsize + j
                    self.assertIsNone(ld.main_object.find_segment_containing(a))
                    self.assertIsNone(ld.main_object.segments.find_region_containing(a))

        self.assertIsNone(ld.main_object.find_segment_containing(0xFFFFFFFF), None)

    def test_sections(self):
        for (arch, filename), data in groundtruth.items():
            self._run_sections(arch, filename, data["sections"])

    def test_segments(self):
        for (arch, filename), data in groundtruth.items():
            self._run_segments(arch, filename, data["segments"])


if __name__ == "__main__":
    unittest.main()
