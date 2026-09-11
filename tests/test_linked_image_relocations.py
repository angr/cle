# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestLinkedImageRelocations(TestCase):
    """
    An image the linker has already finished with, keeping the link-time .rel.text and .rel.data that
    --emit-relocs left behind, the way u-boot's build does.
    """

    def setUp(self):
        self.path = os.path.join(TESTS_BASE, "i386", "linked_with_emit_relocs")
        self.loader = cle.Loader(self.path, auto_load_libs=False)
        self.obj = self.loader.main_object

    def test_link_time_relocations_are_not_applied_again(self):
        # The linker has applied every entry in .rel.text already. A REL entry reads its addend out of memory, so
        # applying it a second time computes S + (S + A) and rewrites the code.
        text = self.obj.sections_map[".text"]
        with open(self.path, "rb") as fp:
            fp.seek(text.offset)
            on_disk = fp.read(text.memsize)
        assert self.loader.memory.load(text.vaddr, text.memsize) == on_disk


if __name__ == "__main__":
    main()
