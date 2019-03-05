import os
import cle
import nose
import logging

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries', 'tests', 'i386'))

def test_preload():
	l = cle.Loader(os.path.join(TESTS_BASE,'test_preload'), auto_load_libs=True, preload_libs=[os.path.join(TESTS_BASE,'test_preload_strcpy_lib.so')])
	s = l.find_symbol('strcpy')
	nose.tools.assert_in('test_preload_strcpy_lib.so', s.owner.binary)
	d = l.find_symbol('do_work')
	nose.tools.assert_false(d.resolved)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_preload()
