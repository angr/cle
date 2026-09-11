#!/usr/bin/env python
from __future__ import annotations

import os

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

import cle
from cle.backends.elf import ELF

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")

# CLE's AArch64 table holds 12 of the static relocation types and 9 dynamic ones, so this object's
# static entries are split: 11 resolve to a class and 31 are discarded.
PARTLY_SUPPORTED = os.path.join(TESTS_BASE, "aarch64", "aarch64-relocs.o")
# Every entry in this one resolves to a class.
FULLY_SUPPORTED = os.path.join(TESTS_BASE, "x86_64", "switch_default_abort.o")
# 902 of this one's 8399 entries are R_PPC_NONE; each of the other 7497 resolves to a class.
R_NONE_HEAVY = os.path.join(TESTS_BASE, "ppc", "partial.o")


def relocation_entries(path):
    """Count relocation entries per type with pyelftools, without going through CLE.

    Returns the counts for the types that apply something, and separately how many R_<arch>_NONE
    entries were seen.
    """
    counts = {}
    r_none = 0
    with open(path, "rb") as stream:
        for section in ELFFile(stream).iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for reloc in section.iter_relocations():
                r_type = reloc.entry.r_info_type
                if r_type == 0:
                    r_none += 1
                else:
                    counts[r_type] = counts.get(r_type, 0) + 1
    return counts, r_none


def load_elf(path) -> ELF:
    obj = cle.Loader(path, auto_load_libs=False).main_object
    assert isinstance(obj, ELF)
    return obj


def test_discarded_relocations_are_counted():
    """An entry CLE has no class for is recorded under its type instead of vanishing."""
    entries, r_none = relocation_entries(PARTLY_SUPPORTED)
    assert (sum(entries.values()), r_none) == (42, 0)

    obj = load_elf(PARTLY_SUPPORTED)
    dropped = obj.unsupported_relocs
    assert dropped, "CLE now handles every relocation type in this fixture; the test needs another"
    assert dropped == {r_type: count for r_type, count in entries.items() if r_type in dropped}
    assert len(obj.relocs) + sum(dropped.values()) == sum(entries.values())


def test_supported_relocations_are_not_counted():
    """The counter stays empty for an object whose entries all resolve to a class."""
    entries, r_none = relocation_entries(FULLY_SUPPORTED)
    assert (sum(entries.values()), r_none) == (20, 0)

    obj = load_elf(FULLY_SUPPORTED)
    assert obj.unsupported_relocs == {}
    assert len(obj.relocs) == sum(entries.values())


def test_r_none_entries_are_not_counted():
    """R_<arch>_NONE applies nothing, so discarding it is not a gap in CLE's coverage."""
    entries, r_none = relocation_entries(R_NONE_HEAVY)
    assert (sum(entries.values()), r_none) == (7497, 902)

    obj = load_elf(R_NONE_HEAVY)
    assert obj.unsupported_relocs == {}
    assert len(obj.relocs) == sum(entries.values())
