from __future__ import annotations

import io
import os
import struct

import cle

# e_machine values, and the note types that appear in a core file
EM_386 = 3
EM_X86_64 = 62
EM_AARCH64 = 183
NT_PRSTATUS = 1
NT_386_TLS = 512
# NetBSD types its per-LWP register note with the number of the PT_GETREGS ptrace request, which is
# PT_FIRSTMACH plus a per-architecture offset.
PT_GETREGS_X86 = 33
PT_GETREGS_AARCH64 = 32


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


def build_note(name, n_type, desc):
    """
    Assemble one ELF note. Both the name and the descriptor are padded out to four bytes.
    """
    note = struct.pack("<III", len(name) + 1, len(desc), n_type) + name + b"\x00"
    note += b"\x00" * (-len(note) % 4)
    return note + desc + b"\x00" * (-len(desc) % 4)


def build_core(machine, bits, notes, vaddr=0x400000, contents=b"\xcc" * 0x100):
    """
    Assemble a minimal little-endian ET_CORE file out of the given notes and a single mapped page.
    """
    ehsize, phentsize = (64, 56) if bits == 64 else (52, 32)
    notes_offset = ehsize + 2 * phentsize
    load_offset = notes_offset + len(notes)

    ident = b"\x7fELF" + bytes([2 if bits == 64 else 1, 1, 1, 0]) + b"\x00" * 8
    if bits == 64:
        header = struct.pack("<HHIQQQIHHHHHH", 4, machine, 1, 0, ehsize, 0, 0, ehsize, phentsize, 2, 0, 0, 0)
        phdrs = struct.pack("<IIQQQQQQ", 4, 4, notes_offset, 0, 0, len(notes), 0, 4)
        phdrs += struct.pack("<IIQQQQQQ", 1, 5, load_offset, vaddr, 0, len(contents), len(contents), 0x1000)
    else:
        header = struct.pack("<HHIIIIIHHHHHH", 4, machine, 1, 0, ehsize, 0, 0, ehsize, phentsize, 2, 0, 0, 0)
        phdrs = struct.pack("<IIIIIIII", 4, notes_offset, 0, 0, len(notes), 0, 4, 4)
        phdrs += struct.pack("<IIIIIIII", 1, load_offset, vaddr, 0, len(contents), len(contents), 5, 0x1000)

    return io.BytesIO(ident + header + phdrs + notes + contents)


def load_core(core):
    """
    Load a synthesized core file, and hand back both the loader and the backend that read its notes.
    """
    ld = cle.Loader(core, main_opts={"backend": "elfcore"}, auto_load_libs=False)
    assert ld.elfcore_object is not None
    return ld, ld.elfcore_object


def freebsd_prstatus(bits, gregset):
    """
    Wrap a register set in a FreeBSD struct prstatus, from sys/sys/procfs.h.
    """
    if bits == 64:
        header = struct.pack("<i4xQQQiii4x", 1, 48 + len(gregset), len(gregset), 512, 1300130, 11, 100654)
    else:
        header = struct.pack("<iIIIiii", 1, 28 + len(gregset), len(gregset), 176, 1300130, 11, 100654)
    return header + gregset


def linux_prstatus_32(gregset, padding=b""):
    """
    Wrap a register set in a 32-bit Linux struct elf_prstatus, from include/uapi/linux/elfcore.h:
    three ints and a short padded to an int, two longs, four ints, four timevals, then the registers
    and pr_fpvalid.
    """
    header = struct.pack("<iiiHxxIIiiii", 11, 1, 0, 11, 0, 0, 100, 99, 100, 100)
    return header + bytes(32) + gregset + struct.pack("<I", 0) + padding


def netbsd_procinfo():
    """
    A struct netbsd_elfcore_procinfo, the descriptor of NetBSD's NT_PRSTATUS. It holds no registers.
    """
    return struct.pack("<IIII", 1, 160, 11, 32767) + b"\x00" * 144


def test_freebsd_prstatus_amd64():
    # struct reg, from sys/x86/include/reg.h
    gregset = struct.pack(
        "<15QIHHIHH5Q",
        0x15,  # r15
        0x14,  # r14
        0x13,  # r13
        0x12,  # r12
        0x11,  # r11
        0x10,  # r10
        0x9,  # r9
        0x8,  # r8
        0xD1,  # rdi
        0x51,  # rsi
        0xB9,  # rbp
        0xBB,  # rbx
        0xDD,  # rdx
        0xCC,  # rcx
        0xAA,  # rax
        0xC,  # trapno
        0x13,  # fs
        0x1B,  # gs
        0x4,  # err
        0x2B,  # es
        0x23,  # ds
        0x400380,  # rip
        0x43,  # cs
        0x246,  # rflags
        0x7FFFFFFFE000,  # rsp
        0x3B,  # ss
    )
    _, core = load_core(build_core(EM_X86_64, 64, build_note(b"FreeBSD", NT_PRSTATUS, freebsd_prstatus(64, gregset))))

    registers = core.thread_registers()
    assert registers["rip"] == 0x400380
    assert registers["rsp"] == 0x7FFFFFFFE000
    assert registers["rax"] == 0xAA
    assert registers["rdi"] == 0xD1
    assert registers["rsi"] == 0x51
    assert registers["rbp"] == 0xB9
    assert registers["r8"] == 0x8
    assert registers["r15"] == 0x15
    assert registers["cs"] == 0x43
    assert registers["eflags"] == 0x246
    # the segment bases live in a note of their own, so FreeBSD's register set has no fs_base
    assert "fs_base" not in registers


def test_freebsd_prstatus_i386():
    # struct reg, from sys/x86/include/reg.h
    gregset = struct.pack(
        "<19I",
        0x33,  # fs
        0x2B,  # es
        0x23,  # ds
        0xD1,  # edi
        0x51,  # esi
        0xB9,  # ebp
        0x19,  # isp
        0xBB,  # ebx
        0xDD,  # edx
        0xCC,  # ecx
        0xAA,  # eax
        0xC,  # trapno
        0x4,  # err
        0x8048400,  # eip
        0x1B,  # cs
        0x246,  # eflags
        0xFFBFE000,  # esp
        0x23,  # ss
        0x3B,  # gs
    )
    _, core = load_core(build_core(EM_386, 32, build_note(b"FreeBSD", NT_PRSTATUS, freebsd_prstatus(32, gregset))))

    registers = core.thread_registers()
    assert registers["eip"] == 0x8048400
    assert registers["esp"] == 0xFFBFE000
    assert registers["eax"] == 0xAA
    assert registers["edi"] == 0xD1
    assert registers["ebp"] == 0xB9
    assert registers["cs"] == 0x1B
    assert registers["eflags"] == 0x246
    assert registers["gs"] == 0x3B


def test_freebsd_prstatus_aarch64():
    # struct reg, from sys/arm64/include/reg.h
    gregset = struct.pack("<33QII", *range(30), 0x400380, 0x7FFFFFFFE000, 0x400400, 0x60000000, 0)
    _, core = load_core(build_core(EM_AARCH64, 64, build_note(b"FreeBSD", NT_PRSTATUS, freebsd_prstatus(64, gregset))))

    registers = core.thread_registers()
    assert registers["pc"] == 0x400400
    assert registers["sp"] == 0x7FFFFFFFE000
    assert registers["x30"] == 0x400380
    assert registers["x0"] == 0
    assert registers["x29"] == 29


def test_netbsd_registers_amd64():
    # struct reg, from sys/arch/amd64/include/reg.h
    gregset = struct.pack(
        "<26Q",
        0xD1,  # rdi
        0x51,  # rsi
        0xDD,  # rdx
        0xCC,  # rcx
        0x8,  # r8
        0x9,  # r9
        0x10,  # r10
        0x11,  # r11
        0x12,  # r12
        0x13,  # r13
        0x14,  # r14
        0x15,  # r15
        0xB9,  # rbp
        0xBB,  # rbx
        0xAA,  # rax
        0x1B,  # gs
        0x13,  # fs
        0x2B,  # es
        0x23,  # ds
        0xC,  # trapno
        0x4,  # err
        0x400380,  # rip
        0x2F,  # cs
        0x246,  # rflags
        0x7F7FFFFFE000,  # rsp
        0x27,  # ss
    )
    notes = build_note(b"NetBSD-CORE", NT_PRSTATUS, netbsd_procinfo())
    notes += build_note(b"NetBSD-CORE@1", PT_GETREGS_X86, gregset)
    _, core = load_core(build_core(EM_X86_64, 64, notes))

    # the procinfo note holds no registers, so it must not have contributed a thread of its own
    assert core.threads == [0]
    registers = core.thread_registers()
    assert registers["rip"] == 0x400380
    assert registers["rsp"] == 0x7F7FFFFFE000
    assert registers["rax"] == 0xAA
    assert registers["rdi"] == 0xD1
    assert registers["rbp"] == 0xB9
    assert registers["r15"] == 0x15
    assert registers["cs"] == 0x2F
    assert registers["eflags"] == 0x246


def test_netbsd_registers_i386():
    # struct reg, from sys/arch/i386/include/reg.h
    gregset = struct.pack(
        "<16I",
        0xAA,  # eax
        0xCC,  # ecx
        0xDD,  # edx
        0xBB,  # ebx
        0xFFBFE000,  # esp
        0xB9,  # ebp
        0x51,  # esi
        0xD1,  # edi
        0x8048400,  # eip
        0x246,  # eflags
        0x1B,  # cs
        0x23,  # ss
        0x2B,  # ds
        0x2B,  # es
        0x33,  # fs
        0x3B,  # gs
    )
    notes = build_note(b"NetBSD-CORE", NT_PRSTATUS, netbsd_procinfo())
    notes += build_note(b"NetBSD-CORE@1", PT_GETREGS_X86, gregset)
    _, core = load_core(build_core(EM_386, 32, notes))

    registers = core.thread_registers()
    assert registers["eip"] == 0x8048400
    assert registers["esp"] == 0xFFBFE000
    assert registers["eax"] == 0xAA
    assert registers["edi"] == 0xD1
    assert registers["ebp"] == 0xB9
    assert registers["gs"] == 0x3B


def test_netbsd_registers_aarch64():
    # struct reg, from sys/arch/aarch64/include/reg.h: r_reg[31], then sp, pc, spsr and tpidr. The
    # note is typed 32 rather than 33, because PT_GETREGS is the first machine-dependent ptrace
    # request on aarch64 and the second on x86.
    gregset = struct.pack("<35Q", *range(31), 0x7FFFFFFFE000, 0x400400, 0x60000000, 0xFC0E044FC000)
    notes = build_note(b"NetBSD-CORE", NT_PRSTATUS, netbsd_procinfo())
    notes += build_note(b"NetBSD-CORE@1", PT_GETREGS_AARCH64, gregset)
    _, core = load_core(build_core(EM_AARCH64, 64, notes))

    registers = core.thread_registers()
    assert registers["pc"] == 0x400400
    assert registers["sp"] == 0x7FFFFFFFE000
    assert registers["x30"] == 30
    assert registers["x29"] == 29


def test_linux_x86_tls_note():
    # Linux writes every register set other than the general purpose and floating point ones under
    # its own name rather than under CORE, NT_386_TLS among them. A loader that looks for it under
    # CORE never finds it and falls back to guessing the thread's TLS region out of memory.
    gregset = struct.pack(
        "<17I",
        0xBB,  # ebx
        0xCC,  # ecx
        0xDD,  # edx
        0x51,  # esi
        0xD1,  # edi
        0xB9,  # ebp
        0xAA,  # eax
        0x2B,  # ds
        0x2B,  # es
        0x0,  # fs
        0x63,  # gs
        0x0,  # orig_eax
        0x8048400,  # eip
        0x23,  # cs
        0x246,  # eflags
        0xFFBFE000,  # esp
        0x2B,  # ss
    )
    # three struct user_desc, the first of which describes the GDT entry gs selects
    tls = struct.pack("<4I", 12, 0xF7FF0700, 0xFFFFF, 0x51)
    tls += struct.pack("<4I", 13, 0, 0, 0x28) + struct.pack("<4I", 14, 0, 0, 0x28)
    notes = build_note(b"CORE", NT_PRSTATUS, linux_prstatus_32(gregset))
    notes += build_note(b"LINUX", NT_386_TLS, tls)
    ld, core = load_core(build_core(EM_386, 32, notes))

    assert core.thread_registers()["eip"] == 0x8048400
    assert ld.tls.threads[0].thread_pointer == 0xF7FF0700


def test_prstatus_abi_mismatch():
    # a Linux x32 core: EM_X86_64 with ELFCLASS32, so cle picks X86, but the note holds an amd64
    # elf_prstatus with 27 eight-byte registers
    gregset = struct.pack("<27Q", *([0] * 16), 0x400380, 0x33, 0x246, 0xFFC0E070, *([0] * 7))
    prstatus = linux_prstatus_32(gregset, bytes(4))
    ld, core = load_core(build_core(EM_X86_64, 32, build_note(b"CORE", NT_PRSTATUS, prstatus)))

    # the registers cannot be represented, but the core's memory still loads
    assert core.threads == []
    assert core.thread_registers() == {}
    assert ld.memory.load(0x400000, 4) == b"\xcc" * 4


if __name__ == "__main__":
    test_remote_file_mapping()
    test_remote_file_mapper()
    test_freebsd_prstatus_amd64()
    test_freebsd_prstatus_i386()
    test_freebsd_prstatus_aarch64()
    test_netbsd_registers_amd64()
    test_netbsd_registers_i386()
    test_netbsd_registers_aarch64()
    test_linux_x86_tls_note()
    test_prstatus_abi_mismatch()
