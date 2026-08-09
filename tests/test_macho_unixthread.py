#!/usr/bin/env python
from __future__ import annotations

import io
import logging
import struct

import cle

# Constants are spelled out here rather than imported from cle so that the expected layouts come
# from the Apple headers and not from the table under test.
MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
CPU_ARCH_ABI64 = 0x1000000
CPU_TYPE_X86 = 0x7
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_ARM = 0xC
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
MH_EXECUTE = 2
MH_TWOLEVEL = 0x80
MH_PIE = 0x200000
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_UNIXTHREAD = 0x5

# thread state flavors, from mach/i386/thread_status.h and mach/arm/thread_status.h
x86_THREAD_STATE32 = 1
x86_THREAD_STATE64 = 4
x86_FLOAT_STATE64 = 5
ARM_THREAD_STATE = 1
ARM_THREAD_STATE64 = 6

PAGE_SIZE = 0x1000


def build_unixthread_executable(cputype: int, flavor: int, thread_state: bytes, text_vaddr: int) -> bytes:
    """
    Assemble a minimal Mach-O executable that takes its entry point from an LC_UNIXTHREAD command.

    :param cputype:         Value for the cputype field of the mach header.
    :param flavor:          Thread state flavor the LC_UNIXTHREAD command announces.
    :param thread_state:    The register block the command carries, laid out as ``cputype`` defines it.
    :param text_vaddr:      Address the __TEXT segment is linked at, __PAGEZERO covers everything below it.
    """
    is64 = bool(cputype & CPU_ARCH_ABI64)

    def segment(segname: bytes, vmaddr: int, vmsize: int, fileoff: int, filesize: int) -> bytes:
        if is64:
            return struct.pack("<2I16s4Q4I", LC_SEGMENT_64, 72, segname, vmaddr, vmsize, fileoff, filesize, 7, 5, 0, 0)
        return struct.pack("<2I16s8I", LC_SEGMENT, 56, segname, vmaddr, vmsize, fileoff, filesize, 7, 5, 0, 0)

    commands = b"".join(
        [
            segment(b"__PAGEZERO", 0, text_vaddr, 0, 0),
            segment(b"__TEXT", text_vaddr, PAGE_SIZE, 0, PAGE_SIZE),
            struct.pack("<6I", LC_SYMTAB, 24, 0, 0, 0, 0),
            unixthread_command(flavor, thread_state),
            thread_state,
        ]
    )
    header = struct.pack(
        "<8I" if is64 else "<7I",
        MH_MAGIC_64 if is64 else MH_MAGIC,
        cputype,
        3,
        MH_EXECUTE,
        4,
        len(commands),
        MH_TWOLEVEL | MH_PIE,
        *([0] if is64 else []),
    )
    return (header + commands).ljust(PAGE_SIZE, b"\0")


def unixthread_command(flavor: int, thread_state: bytes) -> bytes:
    """The 16 byte LC_UNIXTHREAD header, whose count field is the length of the thread state in 32 bit words."""
    return struct.pack("<4I", LC_UNIXTHREAD, 16 + len(thread_state), flavor, len(thread_state) // 4)


def load(cputype: int, flavor: int, thread_state: bytes, text_vaddr: int) -> cle.MachO:
    return load_blob(build_unixthread_executable(cputype, flavor, thread_state, text_vaddr))


def load_blob(blob: bytes) -> cle.MachO:
    ld = cle.Loader(io.BytesIO(blob), main_opts={"backend": "mach-o"})
    assert isinstance(ld.main_object, cle.MachO)
    return ld.main_object


def test_x86_64_thread_state():
    # _STRUCT_X86_THREAD_STATE64 keeps __rip at index 16 of its 21 64 bit fields
    state = [0] * 21
    state[16] = 0x100000F00
    obj = load(CPU_TYPE_X86_64, x86_THREAD_STATE64, struct.pack("<21Q", *state), 0x100000000)
    assert obj.entry == 0x100000F00


def test_x86_thread_state():
    # _STRUCT_X86_THREAD_STATE32 keeps __eip at index 10 of its 16 32 bit fields and __gs last, so a
    # reader that takes the last field it unpacks as the program counter comes back with __gs
    state = [0] * 16
    state[10] = 0x4F00
    state[15] = 0xDEADBEEF
    obj = load(CPU_TYPE_X86, x86_THREAD_STATE32, struct.pack("<16I", *state), 0x4000)
    assert obj.entry == 0x4F00


def test_arm64_thread_state():
    # _STRUCT_ARM_THREAD_STATE64 keeps __pc at index 32 of its 33 64 bit fields, __cpsr and __pad follow
    state = [0] * 33
    state[32] = 0x100000F00
    obj = load(CPU_TYPE_ARM64, ARM_THREAD_STATE64, struct.pack("<33Q2I", *state, 0, 0), 0x100000000)
    assert obj.entry == 0x100000F00


def test_arm_thread_state():
    # _STRUCT_ARM_THREAD_STATE keeps __pc at index 15 of its 17 32 bit fields, __cpsr follows
    state = [0] * 17
    state[15] = 0x4F00
    obj = load(CPU_TYPE_ARM, ARM_THREAD_STATE, struct.pack("<17I", *state), 0x4000)
    assert obj.entry == 0x4F00


def test_flavor_without_a_known_layout_still_loads():
    # x86_FLOAT_STATE64 carries no program counter, so the binary loads without an entry point instead of failing
    obj = load(CPU_TYPE_X86_64, x86_FLOAT_STATE64, b"\0" * 168, 0x100000000)
    assert obj.entry == 0


def test_thread_state_shorter_than_its_flavor_still_loads():
    # Two words is nowhere near an x86_thread_state64_t, so there is no __rip to read behind the command
    obj = load(CPU_TYPE_X86_64, x86_THREAD_STATE64, struct.pack("<2I", 0, 0), 0x100000000)
    assert obj.entry == 0
    assert obj.unixthread_pc is None


def test_thread_state_running_past_the_end_of_the_file_still_loads():
    state = [0] * 21
    state[16] = 0x100000F00
    thread_state = struct.pack("<21Q", *state)
    blob = build_unixthread_executable(CPU_TYPE_X86_64, x86_THREAD_STATE64, thread_state, 0x100000000)
    command = unixthread_command(x86_THREAD_STATE64, thread_state)
    obj = load_blob(blob[: blob.index(command) + len(command) + 8])
    assert obj.entry == 0
    assert obj.unixthread_pc is None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_x86_64_thread_state()
    test_x86_thread_state()
    test_arm64_thread_state()
    test_arm_thread_state()
    test_flavor_without_a_known_layout_still_loads()
    test_thread_state_shorter_than_its_flavor_still_loads()
    test_thread_state_running_past_the_end_of_the_file_still_loads()
