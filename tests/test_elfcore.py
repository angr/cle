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
    ld = cle.Loader(
        get_coredump_file(),
        main_opts={"backend": "elfcore", "remote_file_mapping": remote_file_mapping},
        auto_load_libs=True,
    )
    check_objects_loaded(ld)


def test_remote_file_mapper():
    directory_for_binaries = get_binary_directory()

    def remote_file_mapper(x):
        return x.replace("/tmp/foobar/does-not-exist", directory_for_binaries)

    ld = cle.Loader(
        get_coredump_file(),
        main_opts={"backend": "elfcore", "remote_file_mapper": remote_file_mapper},
        auto_load_libs=True,
    )
    check_objects_loaded(ld)


def test_blob_children_keep_the_mapping_permissions():
    """A core states what each mapping was allowed to do, and the blobs cut out of it say the same."""
    directory_for_binaries = get_binary_directory()
    ld = cle.Loader(
        get_coredump_file(),
        main_opts={
            "backend": "elfcore",
            "remote_file_mapper": lambda x: x.replace("/tmp/foobar/does-not-exist", directory_for_binaries),
        },
        auto_load_libs=True,
    )

    core = ld.elfcore_object
    assert core is not None
    blobs = [obj for obj in ld.all_objects if isinstance(obj, cle.Blob)]
    assert blobs, "the core's leftover mappings should have become blobs"

    for blob in blobs:
        for segment in blob.segments:
            source = core.segments.find_region_containing(segment.vaddr)
            assert source is not None
            assert (segment.is_readable, segment.is_writable, segment.is_executable) == (
                source.is_readable,
                source.is_writable,
                source.is_executable,
            ), f"{segment} does not describe the mapping {source} it was cut from"

    # the heap and the stack are in there, and they are not code
    assert any(not segment.is_executable for blob in blobs for segment in blob.segments)
