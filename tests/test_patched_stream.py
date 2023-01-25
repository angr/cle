import os
from io import BytesIO

import cle

tests_path = os.path.join(os.path.dirname(__file__), "..", "..", "binaries", "tests")


def test_patched_stream():
    stream = BytesIO(b"0123456789abcdef")

    stream1 = cle.PatchedStream(stream, [(2, b"AA")])
    stream1.seek(0)
    assert stream1.read() == b"01AA456789abcdef"

    stream2 = cle.PatchedStream(stream, [(2, b"AA")])
    stream2.seek(0)
    assert stream2.read(3) == b"01A"

    stream3 = cle.PatchedStream(stream, [(2, b"AA")])
    stream3.seek(3)
    assert stream3.read(3) == b"A45"

    stream4 = cle.PatchedStream(stream, [(-1, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")])
    stream4.seek(0)
    assert stream4.read() == b"A" * 0x10


def test_malformed_sections():
    ld = cle.Loader(os.path.join(tests_path, "i386", "oxfoo1m3"))
    assert len(ld.main_object.segments) == 1
    assert len(ld.main_object.sections) == 0
