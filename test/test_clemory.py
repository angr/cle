
import cffi
import nose.tools

import cle

def test_cclemory():
    """
    This is a test case for C-backed Clemory.
    """

    clemory = cle.Clemory(None)
    clemory.add_backer(0, "\x90" * 1000)
    clemory.add_backer(2000, "A" * 1000)
    clemory.add_backer(3000, "ABCDEFGH")
    clemory.flatten_to_c()

    ffi = cffi.FFI()
    ffi.cdef("""
        int memcmp(const void* s1, const void* s2, size_t n);
    """)
    c = ffi.verify("""
        #include <string.h>
    """)

    bytes = clemory.read_bytes_c(0)
    out = c.memcmp(ffi.new("unsigned char []", "\x90" * 10), bytes, 10)
    nose.tools.assert_equal(out, 0)

    bytes = clemory.read_bytes_c(2000)
    out = c.memcmp(ffi.new("unsigned char []", "B" * 1000), bytes, 1000)
    nose.tools.assert_not_equal(out, 0)
    out = c.memcmp(ffi.new("unsigned char []", "A" * 1000), bytes, 1000)
    nose.tools.assert_equal(out, 0)

    bytes = clemory.read_bytes_c(3000)
    out = c.memcmp(ffi.new("unsigned char []", "ABCDEFGH"), bytes, 8)
    nose.tools.assert_equal(out, 0)

def main():
    g = globals()
    for func_name, func in g.iteritems():
        if func_name.startswith('test_') and hasattr(func, '__call__'):
            func()

if __name__ == "__main__":
    main()