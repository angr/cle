from __future__ import annotations

import os

import cle


def get_coredump_file():
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "../../binaries/tests/x86_64/coredump/true-libc.so.6-ld-linux-x86-64.so.2.core",
    )


def get_binary_directory():
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests/x86_64")


def check_objects_loaded(ld):
    # we should have child objects if everything loaded correctly
    assert ld.elfcore_object.child_objects
    for _, _, _, fn in ld.elfcore_object.filename_lookup:
        assert "/tmp/foobar/does-not-exist" not in fn


def test_remote_file_mapping():
    remote_file_mapping = {
        "/tmp/foobar/does-not-exist/true": f"{get_binary_directory()}/true",
        "/tmp/foobar/does-not-exist/libc.so.6": f"{get_binary_directory()}/libc.so.6",
        "/tmp/foobar/does-not-exist/ld-linux-x86-64.so.2": f"{get_binary_directory()}/ld-linux-x86-64.so.2",
    }
    ld = cle.Loader(get_coredump_file(), main_opts={"backend": "elfcore", "remote_file_mapping": remote_file_mapping})
    check_objects_loaded(ld)


def test_remote_file_mapper():
    directory_for_binaries = get_binary_directory()

    def remote_file_mapper(x):
        return x.replace("/tmp/foobar/does-not-exist", directory_for_binaries)

    ld = cle.Loader(get_coredump_file(), main_opts={"backend": "elfcore", "remote_file_mapper": remote_file_mapper})
    check_objects_loaded(ld)
