import nose
import StringIO
import os

import cle

tests_path = os.path.join(os.path.dirname(__file__), '..', '..', 'binaries', 'tests')

def test_patched_stream():
    stream = StringIO.StringIO('0123456789abcdef')

    stream1 = cle.PatchedStream(stream, [(2, 'AA')])
    stream1.seek(0)
    nose.tools.assert_equal(stream1.read(), '01AA456789abcdef')

    stream2 = cle.PatchedStream(stream, [(2, 'AA')])
    stream2.seek(0)
    nose.tools.assert_equal(stream2.read(3), '01A')

    stream3 = cle.PatchedStream(stream, [(2, 'AA')])
    stream3.seek(3)
    nose.tools.assert_equal(stream3.read(3), 'A45')

    stream4 = cle.PatchedStream(stream, [(-1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')])
    stream4.seek(0)
    nose.tools.assert_equal(stream4.read(), 'A'*0x10)

def test_malformed_sections():
    ld = cle.Loader(os.path.join(tests_path, 'i386', 'oxfoo1m3'))
    nose.tools.assert_equal(len(ld.main_object.segments), 1)
    nose.tools.assert_equal(len(ld.main_object.sections), 0)
