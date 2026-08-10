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
    assert len(ld.main_object.sections) == 30

    sections_map = ld.main_object.sections_map
    assert "jusched.exe" in sections_map
    assert "kernel32.dll" in sections_map

    # A minidump has no per-module section table to derive permissions from, so every module is fully permissive.
    jusched = sections_map["jusched.exe"]
    assert jusched.is_readable
    assert jusched.is_writable
    assert jusched.is_executable
    assert not jusched.only_contains_uninitialized_data

    # jusched.exe is captured whole, in five ranges that are adjacent both in memory and in the file, so its
    # section covers the entire image and the last bytes of the image are readable from the file offset it gives.
    assert jusched.memsize == 0x92000
    assert jusched.filesize == jusched.memsize
    assert ld.memory.load(jusched.vaddr, 2) == pefile.IMAGE_DOS_SIGNATURE.to_bytes(2, "little")
    assert jusched.addr_to_offset(jusched.vaddr) == jusched.offset
    with open(exe, "rb") as fp:
        fp.seek(jusched.addr_to_offset(jusched.max_addr - 15))
        assert fp.read(16) == ld.memory.load(jusched.max_addr - 15, 16)

    # Only the first page of kernel32.dll was captured, so its section maps that much of the image and no more.
    kernel32 = sections_map["kernel32.dll"]
    assert kernel32.memsize == 0x140000
    assert kernel32.filesize == 0x1000
    assert not kernel32.only_contains_uninitialized_data
    assert kernel32.addr_to_offset(kernel32.vaddr + kernel32.filesize) is None

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
    assert "test_app.exe" in obj.sections_map
    assert "kernel32.dll" in obj.sections_map

    # Uncaptured modules still get a section, so an analysis can tell which module an address belongs to, but the
    # section maps no file bytes.
    assert all(section.memsize > 0 for section in obj.sections)
    assert all(section.filesize == 0 for section in obj.sections)
    assert all(section.only_contains_uninitialized_data for section in obj.sections)
    assert all(section.addr_to_offset(section.vaddr) is None for section in obj.sections)

    ntdll = obj.sections_map["ntdll.dll"]
    assert ntdll.vaddr == 0x7C900000
    assert ntdll.memsize == 0xB0000
    # The one captured code range lives inside ntdll but does not start at its base address.
    assert ld.memory.load(0x7C90EB14, 4) == bytes.fromhex("ff83c4ec")

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
    test_partial_minidump()
