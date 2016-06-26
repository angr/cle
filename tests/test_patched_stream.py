import nose
import StringIO

import cle

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
