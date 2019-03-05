import cle
import nose
import logging

def test_preload():
	l = cle.Loader('./test_preload', auto_load_libs=True, preload_libs=['./strcpy_lib.so'])
	s = l.find_symbol('strcpy')
	nose.tools.assert_in('strcpy_lib.so', s.owner.binary)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_preload()
