# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os
from unittest import TestCase, main

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestGnuHashResiliency(TestCase):
    def test_zeroed_hash_tables(self):
        """
        A hash table of all zeroes declares no buckets, which is not a reason to give up on the file.

        gnu_hash_resiliency_0 is test_killing_ref with the bytes of its DT_HASH and DT_GNU_HASH
        tables zeroed, the way some stripping and obfuscation tools leave a binary. Everything the
        loader actually needs survives that, so the two must come out the same.
        """
        corrupt = cle.Loader(os.path.join(TESTS_BASE, "x86_64", "gnu_hash_resiliency_0"), auto_load_libs=False)
        intact = cle.Loader(os.path.join(TESTS_BASE, "x86_64", "test_killing_ref"), auto_load_libs=False)

        assert corrupt.main_object.entry == intact.main_object.entry
        assert sorted(corrupt.main_object.imports) == sorted(intact.main_object.imports)
        assert len(corrupt.main_object.relocs) == len(intact.main_object.relocs)
        assert sorted((s.name, s.relative_addr) for s in corrupt.main_object.symbols) == sorted(
            (s.name, s.relative_addr) for s in intact.main_object.symbols
        )
        assert corrupt.main_object.get_symbol("main") is not None


if __name__ == "__main__":
    main()
