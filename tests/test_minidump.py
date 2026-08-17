from __future__ import annotations

import os
import unittest

import archinfo

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


@unittest.skipIf(cle.backends.minidump.minidumpfile is None, "minidump not available")
def test_minidump():
    exe = os.path.join(TEST_BASE, "tests", "x86", "windows", "jusched_x86.dmp")
    ld = cle.Loader(exe, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.Minidump)
    assert isinstance(ld.main_object.arch, archinfo.ArchX86)
    assert ld.main_object.os == "windows"
    # One section per section of each of the 30 loaded modules, read out of the images the dump mapped.
    assert len(ld.main_object.sections) == 182

    sections_map = ld.main_object.sections_map
    assert "jusched.exe:.text" in sections_map
    assert "kernel32.dll:.text" in sections_map

    text = sections_map["kernel32.dll:.text"]
    assert (text.is_readable, text.is_writable, text.is_executable) == (True, False, True)
    data = sections_map["kernel32.dll:.data"]
    assert (data.is_readable, data.is_writable, data.is_executable) == (True, True, False)

    assert sum(1 for section in ld.main_object.sections if section.is_executable) == 40

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


@unittest.skipIf(cle.backends.minidump.minidumpfile is None, "minidump not available")
def test_minidump_sections_state_their_permissions():
    """A dump's sections used to be built from the abstract base class, so asking raised NotImplementedError."""
    exe = os.path.join(TEST_BASE, "tests", "x86", "windows", "jusched_x86.dmp")
    ld = cle.Loader(exe, auto_load_libs=False)

    executable = [section for section in ld.main_object.sections if section.is_executable]
    assert executable
    assert all(section.is_readable for section in executable)
    # the code of a loaded module is a fraction of the module, and a much smaller fraction of the dump
    assert sum(section.memsize for section in executable) < sum(section.memsize for section in ld.main_object.sections)


if __name__ == "__main__":
    test_minidump()
    test_minidump_sections_state_their_permissions()
