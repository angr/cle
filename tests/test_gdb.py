from __future__ import annotations

import os

import cle

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests"))
binpath = os.path.join(test_location, "x86_64/test_gdb_plugin")
cle.GDB_SEARCH_PATH.insert(0, os.path.join(test_location, "x86_64"))


def check_addrs(ld):
    libc = ld.shared_objects["libc.so.6"]
    ld = ld.shared_objects["ld-linux-x86-64.so.2"]
    assert libc.mapped_base == 0x7FFFF7A17000
    assert ld.mapped_base == 0x7FFFF7DDC000


def test_info_proc_maps():
    mappath = os.path.join(test_location, "../tests_data/test_gdb_plugin/procmap")
    ld = cle.Loader(binpath, **cle.convert_info_proc_maps(mappath))
    check_addrs(ld)


def test_info_sharedlibrary():
    mappath = os.path.join(test_location, "../tests_data/test_gdb_plugin/info_sharedlibs")
    ld = cle.Loader(binpath, **cle.convert_info_sharedlibrary(mappath))
    check_addrs(ld)


if __name__ == "__main__":
    test_info_proc_maps()
    test_info_sharedlibrary()
