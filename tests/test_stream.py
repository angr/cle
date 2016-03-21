#!/usr/bin/env python

import cle
import nose
import os

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_stream():
    dirpath = os.path.join(test_location, "x86_64")
    filepath = os.path.join(dirpath, "fauxware")
    filestream = open(filepath, 'rb')

    load_opts = {'custom_ld_path': [dirpath]}

    path_ld = cle.Loader(filepath, **load_opts)
    stream_ld = cle.Loader(filestream, **load_opts)

    nose.tools.assert_equal(path_ld.main_bin.entry, stream_ld.main_bin.entry)
    nose.tools.assert_equal(path_ld.shared_objects.keys(), stream_ld.shared_objects.keys())
    nose.tools.assert_equal(path_ld.memory.read_addr_at(path_ld.main_bin.entry),
                            stream_ld.memory.read_addr_at(stream_ld.main_bin.entry))

if __name__ == '__main__':
    test_stream()
