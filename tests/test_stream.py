#!/usr/bin/env python
from __future__ import annotations

import os

import cle

test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


def test_stream():
    dirpath = os.path.join(test_location, "i386")
    filepath = os.path.join(dirpath, "fauxware")
    lib1path = os.path.join(dirpath, "libc.so.6")
    lib2path = os.path.join(dirpath, "ld-linux.so.2")

    path_ld = cle.Loader(filepath)
    stream_ld = cle.Loader(
        open(filepath, "rb"),
        auto_load_libs=False,
        preload_libs=(open(lib1path, "rb"), open(lib2path, "rb")),
    )

    assert path_ld.main_object.entry == stream_ld.main_object.entry
    assert [x for x in path_ld.shared_objects.keys() if x != "fauxware"] == list(stream_ld.shared_objects.keys())
    assert path_ld.memory.unpack_word(path_ld.main_object.entry) == stream_ld.memory.unpack_word(
        stream_ld.main_object.entry
    )
    strcmp_string = path_ld.describe_addr(path_ld.memory.unpack_word(0x804A000))
    assert "libc.so.6" in strcmp_string
    assert "strcmp" in strcmp_string
    assert strcmp_string == stream_ld.describe_addr(stream_ld.memory.unpack_word(0x804A000))


if __name__ == "__main__":
    test_stream()
