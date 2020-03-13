import nose
import cle

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                             os.path.join('..', '..', 'binaries', 'tests'))

def test_progname():
    filename = os.path.join(test_location, 'x86_64', 'cat')
    ld = cle.Loader(filename, auto_load_libs=False)
    progname_ptr_symbol = ld.find_symbol('__progname')
    progname_ptr = ld.memory.unpack_word(progname_ptr_symbol.rebased_addr)

    nose.tools.assert_not_equal(progname_ptr, 0)

    progname = ld.memory.load(progname_ptr, 8)
    nose.tools.assert_equal(progname, b'program\0')

def test_got_relocation():
    filename = os.path.join(test_location, 'x86_64', 'multiarch_main_main.o')
    ld = cle.Loader(filename)

    reloc = ld.main_object.relocs[1]
    nose.tools.assert_equal(reloc.symbol.name, 'vex_failure_exit')  # this should never fail
    nose.tools.assert_equal(reloc.symbol.resolvedby.name, 'got.vex_failure_exit')

    ptr = ld.memory.unpack_word(reloc.symbol.resolvedby.rebased_addr)
    final_symbol = ld.find_symbol(ptr)

    nose.tools.assert_is_not(final_symbol, None)
    nose.tools.assert_equal(final_symbol.name, 'vex_failure_exit')
    nose.tools.assert_true(final_symbol.is_extern)

if __name__ == '__main__':
    test_progname()
    test_got_relocation()
