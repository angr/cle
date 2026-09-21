from __future__ import annotations

import io
import os
import struct
from collections.abc import Iterable

import archinfo
import pytest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

# A 32-bit Windows dump of the Java update scheduler, with modules, threads and its memory in a Memory64List.
JUSCHED = os.path.join(TEST_BASE, "tests", "x86", "windows", "jusched_x86.dmp")
# A 64-bit Windows dump of a crashing test program, from Breakpad's processor test data.
TINY_EXE = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "breakpad", "tiny-exe-with-cet-xsave.dmp")

UNUSED_STREAM = 0
THREAD_LIST_STREAM = 3
MODULE_LIST_STREAM = 4
MEMORY_LIST_STREAM = 5
SYSTEM_INFO_STREAM = 7

MINIDUMP_DIRECTORY_ENTRY_SIZE = 12


def without_streams(path: str, stream_types: Iterable[int]) -> io.BytesIO:
    """
    Read the dump at `path` and mark the given streams unused in its stream directory.

    A minidump holds only the streams its writer collected, and a writer that reserved a directory entry for a
    stream it did not write leaves that entry's type as UnusedStream; every dump used here already carries such
    entries. Striking a stream out of the directory of a real dump is how the cases below get a dump that never
    recorded its modules, its threads or its memory.
    """

    struck_out = set()
    wanted = set(stream_types)
    with open(path, "rb") as dump:
        data = bytearray(dump.read())
    # the signature and the version take the first eight bytes of the header, the stream count and the file
    # offset of the directory the next eight
    number_of_streams, directory_rva = struct.unpack_from("<II", data, 8)
    for index in range(number_of_streams):
        entry = directory_rva + MINIDUMP_DIRECTORY_ENTRY_SIZE * index
        (stream_type,) = struct.unpack_from("<I", data, entry)
        if stream_type in wanted:
            struct.pack_into("<I", data, entry, UNUSED_STREAM)
            struck_out.add(stream_type)
    assert struck_out == wanted, f"{path} lists no stream of type {sorted(wanted - struck_out)}"
    return io.BytesIO(bytes(data))


def test_minidump():
    ld = cle.Loader(JUSCHED, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.Minidump)
    assert isinstance(ld.main_object.arch, archinfo.ArchX86)
    assert ld.main_object.os == "windows"
    assert len(ld.main_object.sections) == 30

    sections_map = ld.main_object.sections_map
    assert "jusched.exe" in sections_map
    assert "kernel32.dll" in sections_map

    assert len(ld.main_object.threads) == 2
    registers = ld.main_object.thread_registers(0x0548)
    assert isinstance(registers, dict)
    assert registers == {
        #'gs': 43,
        #'fs': 83,
        # currently we return the fs segment base value instead of the register itself
        "fs": 2121117696,
        "edi": 2001343136,
        "esi": 2001343136,
        "ebx": 0,
        "edx": 2001343136,
        "ecx": 2001343136,
        "eax": 2121117696,
        "ebp": 33357196,
        "eip": 2000776736,
        "eflags": 580,
        "esp": 33357152,
    }


def test_minidump_without_module_list():
    # A dump without a ModuleListStream says nothing about which images were loaded, but its memory and its
    # threads are still there to be used. On AMD64 the architecture is decided by looking through the module list
    # for wow64.dll, and here there is no module list to look through.
    ld = cle.Loader(without_streams(TINY_EXE, [MODULE_LIST_STREAM]), auto_load_libs=False)

    assert isinstance(ld.main_object, cle.Minidump)
    assert isinstance(ld.main_object.arch, archinfo.ArchAMD64)
    assert not ld.main_object.wow64
    assert len(ld.main_object.segments) == 65
    assert len(ld.main_object.sections) == 0
    assert ld.main_object.sections_map == {}

    assert ld.main_object.threads == [0x5BC]
    registers = ld.main_object.thread_registers(0x5BC)
    assert registers["rip"] == 0x7FF9111E39E4
    assert registers["rsp"] == 0xCBC82FF448
    assert len(ld.tls.threads) == 1


def test_minidump_without_thread_list():
    # A dump without a ThreadListStream has no register state, and its modules and memory still load.
    ld = cle.Loader(without_streams(JUSCHED, [THREAD_LIST_STREAM]), auto_load_libs=False)

    assert len(ld.main_object.segments) == 173
    assert len(ld.main_object.sections) == 30
    assert "jusched.exe" in ld.main_object.sections_map
    assert ld.main_object.threads == []
    assert ld.tls.threads == []


def test_minidump_without_captured_memory():
    # A dump that captured no memory is not an invalid dump; it just has nothing to map. Without memory there is
    # no image to attach a module to and no TEB to read a thread's registers through, so this is a dump whose
    # writer recorded none of the three.
    ld = cle.Loader(
        without_streams(TINY_EXE, [MEMORY_LIST_STREAM, MODULE_LIST_STREAM, THREAD_LIST_STREAM]), auto_load_libs=False
    )

    assert isinstance(ld.main_object, cle.Minidump)
    assert isinstance(ld.main_object.arch, archinfo.ArchAMD64)
    assert len(ld.main_object.segments) == 0
    assert len(ld.main_object.sections) == 0
    assert ld.main_object.threads == []
    assert ld.tls.threads == []


def test_minidump_without_system_info():
    # The architecture is the one thing the backend cannot do without, and the error saying so has to be a CLEError
    # that carries its explanation.
    dump = without_streams(TINY_EXE, [SYSTEM_INFO_STREAM])
    with pytest.raises(cle.CLEError, match="SystemInfoStream is missing") as excinfo:
        cle.Loader(dump, auto_load_libs=False)
    assert isinstance(excinfo.value, cle.backends.minidump.MinidumpMissingStreamError)


if __name__ == "__main__":
    test_minidump()
    test_minidump_without_module_list()
    test_minidump_without_thread_list()
    test_minidump_without_captured_memory()
    test_minidump_without_system_info()
