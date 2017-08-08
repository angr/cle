
import cffi
import nose.tools

import cle

def test_cclemory():
    # This is a test case for C-backed Clemory.

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, "\x90" * 1000)
    clemory.add_backer(2000, "A" * 1000)
    clemory.add_backer(3000, "ABCDEFGH")
    clemory._flatten_to_c()

    ffi = cffi.FFI()
    ffi.cdef("""
        int memcmp(const void* s1, const void* s2, size_t n);
    """)
    c = ffi.verify("""
        #include <string.h>
    """)
    # pylint: disable=no-member
    byte_str = clemory.read_bytes_c(0)[0]
    out = c.memcmp(ffi.new("unsigned char []", "\x90" * 10), byte_str, 10)
    nose.tools.assert_equal(out, 0)

    byte_str = clemory.read_bytes_c(2000)[0]
    out = c.memcmp(ffi.new("unsigned char []", "B" * 1000), byte_str, 1000)
    nose.tools.assert_not_equal(out, 0)
    out = c.memcmp(ffi.new("unsigned char []", "A" * 1000), byte_str, 1000)
    nose.tools.assert_equal(out, 0)

    byte_str = clemory.read_bytes_c(3000)[0]
    out = c.memcmp(ffi.new("unsigned char []", "ABCDEFGH"), byte_str, 8)
    nose.tools.assert_equal(out, 0)

def test_clemory():
    # directly write bytes to backers
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, "A" * 20)
    clemory.add_backer(20, "A" * 20)
    clemory.add_backer(50, "A" * 20)
    nose.tools.assert_equal(len(clemory._backers), 3)

    clemory.write_bytes_to_backer(10, "B" * 70)

    nose.tools.assert_equal(len(clemory._backers), 4)
    nose.tools.assert_equal("".join(clemory.read_bytes(0, 80)), "A" * 10 + "B" * 70)


    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(10, "A" * 20)
    clemory.add_backer(50, "A" * 20)
    nose.tools.assert_equal(len(clemory._backers), 2)
    clemory.write_bytes_to_backer(0, "") # Should not except out
    nose.tools.assert_equal(len(clemory._backers), 2)
    clemory.write_bytes_to_backer(0, "B" * 10)
    nose.tools.assert_equal(len(clemory._backers), 3)
    nose.tools.assert_equal("".join(clemory.read_bytes(0, 25)), "B" * 10 + "A" * 15)

def main():
    g = globals()
    for func_name, func in g.iteritems():
        if func_name.startswith('test_') and hasattr(func, '__call__'):
            func()

if __name__ == "__main__":
    main()
