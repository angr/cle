from __future__ import annotations

import os
import unittest

import archinfo
import pefile

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

    # The image is mapped headers and all, which is what makes its own section table readable back out of the dump.
    assert ld.memory.load(0x140000, 2) == pefile.IMAGE_DOS_SIGNATURE.to_bytes(2, "little")

    # This dump captured every module whole, so each section holds as many file bytes as it spans in memory, and
    # the file offset it reports reads back the bytes the dump has at that address.
    text = sections_map["jusched.exe:.text"]
    assert text.filesize == text.memsize
    assert not text.only_contains_uninitialized_data
    with open(exe, "rb") as fp:
        fp.seek(text.addr_to_offset(text.max_addr - 15))
        assert fp.read(16) == ld.memory.load(text.max_addr - 15, 16)

    assert len(ld.main_object.threads) == 2
    assert len(ld.tls.threads) == 2
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


@unittest.skipIf(cle.backends.minidump.minidumpfile is None, "minidump not available")
def test_partial_minidump():
    # A crash dump this small captures the faulting instruction and the thread stacks and nothing else, so not one
    # of the modules it lists is captured at its base address.
    exe = os.path.join(TEST_BASE, "tests", "x86", "windows", "partial", "minidump2.dmp")
    ld = cle.Loader(exe, auto_load_libs=False)
    obj = ld.main_object

    assert isinstance(obj, cle.Minidump)
    assert isinstance(obj.arch, archinfo.ArchX86)
    assert obj.os == "windows"
    assert len(obj.segments) == 3
    assert len(obj.sections) == 13

    # An uncaptured module has no readable header, so it falls back to one section spanning the image. That section
    # still places the module, which is what tells an analysis whose address an address is, but it maps no file
    # bytes and it claims no permission it cannot support.
    assert "test_app.exe" in obj.sections_map
    assert "kernel32.dll" in obj.sections_map
    assert all(section.memsize > 0 for section in obj.sections)
    assert all(section.filesize == 0 for section in obj.sections)
    assert all(section.only_contains_uninitialized_data for section in obj.sections)
    assert all(section.addr_to_offset(section.vaddr) is None for section in obj.sections)

    ntdll = obj.sections_map["ntdll.dll"]
    assert ntdll.vaddr == 0x7C900000
    assert ntdll.memsize == 0xB0000
    # The one captured code range lives inside ntdll but does not start at its base address, and what the loader
    # serves there is what the dump file holds for it.
    assert ntdll.contains_addr(0x7C90EB14)
    captured = next(segment for segment in obj.segments if segment.contains_addr(0x7C90EB14))
    with open(exe, "rb") as fp:
        fp.seek(captured.offset + 0x7C90EB14 - captured.vaddr)
        assert fp.read(4) == ld.memory.load(0x7C90EB14, 4)

    # The TEB pages are not captured, so the general-purpose registers survive without the fs segment base.
    assert obj.threads == [0x0BF4, 0x11C0]
    assert obj.thread_registers(0x0BF4) == {
        "edi": 0x0,
        "esi": 0x7B8,
        "ebx": 0x7C883780,
        "edx": 0x7C97C0D8,
        "ecx": 0x7C80B46E,
        "eax": 0x400000,
        "ebp": 0x12F384,
        "eip": 0x7C90EB94,
        "eflags": 0x246,
        "esp": 0x12F320,
    }

    # Without a TEB there is no way to reach a thread's TLS array, so no thread is modeled rather than the load
    # failing outright.
    assert not ld.tls.threads


if __name__ == "__main__":
    test_minidump()
    test_minidump_sections_state_their_permissions()
    test_partial_minidump()
