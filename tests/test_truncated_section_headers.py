from __future__ import annotations

import os

import cle
from cle import ELF
from cle.backends.elf.metaelf import Relro

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
TRUNCATED = os.path.join(TEST_BASE, "tests", "armel", "fauxware.truncated.elf")


def test_section_header_table_past_eof():
    """A section header table that starts past the end of the file must not lose the load."""
    # The fixture is tests/armel/fauxware cut at the end of its last PT_LOAD, so every byte the
    # program headers call loadable is present and the section header table is gone. PT_DYNAMIC and
    # PT_GNU_RELRO are both still there, which is what makes the RELRO probe in MetaELF.__init__
    # read the table -- before ELF.__init__ gets the chance to fall back on the program headers.
    obj = cle.Loader(TRUNCATED, auto_load_libs=False).main_object
    assert isinstance(obj, ELF)

    assert obj.entry == 0x84AD
    assert len(obj.segments) == 3
    assert len(obj.sections) == 0
    assert obj.deps == ["libc.so.6", "ld-linux-armhf.so.3"]
    # The section header table is where BIND_NOW would have been read from, so the level cannot be
    # told apart from no RELRO at all.
    assert obj.relro is Relro.NONE


def test_section_header_table_past_eof_discarded():
    """discard_section_headers is documented for section headers that are corrupt or malicious."""
    obj = cle.Loader(TRUNCATED, auto_load_libs=False, main_opts={"discard_section_headers": True}).main_object

    assert obj.entry == 0x84AD
    assert len(obj.sections) == 0
