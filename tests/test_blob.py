from __future__ import annotations

import os
import pickle

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_blob_0():
    BASE_ADDR = 0x8000000
    ENTRYPOINT = 0x8001337

    blob_file = os.path.join(TEST_BASE, "tests", "i386", "all")
    blob_file_size = os.stat(blob_file).st_size
    ld = cle.Loader(
        blob_file,
        main_opts={
            "backend": "blob",
            "base_addr": BASE_ADDR,
            "entry_point": ENTRYPOINT,
            "arch": "ARM",
        },
    )

    assert ld.main_object.linked_base == BASE_ADDR
    assert ld.main_object.mapped_base == BASE_ADDR
    assert ld.main_object.min_addr == BASE_ADDR
    assert ld.main_object.max_addr == BASE_ADDR + blob_file_size - 1
    assert ld.main_object.entry == ENTRYPOINT
    assert ld.main_object.contains_addr(BASE_ADDR)
    assert not ld.main_object.contains_addr(BASE_ADDR - 1)

    # ensure that pickling works
    ld_pickled = pickle.loads(pickle.dumps(ld))
    assert ld_pickled.main_object.mapped_base == BASE_ADDR


def test_blob_1():
    # Make sure the base address behaves as expected regardless of whether offset is specified or not.

    BASE_ADDR = 0x8000000
    ENTRYPOINT = 0x8001337

    blob_file = os.path.join(TEST_BASE, "tests", "i386", "all")
    offset = 0x200
    blob_file_size = os.stat(blob_file).st_size - offset
    ld = cle.Loader(
        blob_file,
        main_opts={
            "backend": "blob",
            "base_addr": BASE_ADDR,
            "entry_point": ENTRYPOINT,
            "arch": "ARM",
            "offset": offset,
        },
    )

    assert ld.main_object.linked_base == BASE_ADDR
    assert ld.main_object.mapped_base == BASE_ADDR
    assert ld.main_object.min_addr == BASE_ADDR
    assert ld.main_object.max_addr == BASE_ADDR + blob_file_size - 1
    assert ld.main_object.entry == ENTRYPOINT


if __name__ == "__main__":
    test_blob_0()
    test_blob_1()
