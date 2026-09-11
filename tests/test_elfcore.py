from __future__ import annotations

import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def get_coredump_file():
    return os.path.join(TEST_BASE, "x86_64", "coredump", "true-libc.so.6-ld-linux-x86-64.so.2.core")


def get_binary_directory():
    return os.path.join(TEST_BASE, "x86_64")


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


def load_core(arch, name):
    """
    Load one of the core dump fixtures, and hand back both the loader and the backend that read its
    notes. The fixtures below were written by the kernel named in each test; a core assembled by hand
    would have a shape no kernel emits, which is exactly what these tests are here to catch.
    """
    ld = cle.Loader(os.path.join(TEST_BASE, arch, name), main_opts={"backend": "elfcore"}, auto_load_libs=False)
    assert ld.elfcore_object is not None
    return ld, ld.elfcore_object


def test_freebsd_prstatus_amd64():
    # FreeBSD's NT_PRSTATUS is a struct prstatus from sys/sys/procfs.h, 224 bytes here, and shares no
    # prefix with the Linux struct of the same note type. The registers are a struct reg from
    # sys/x86/include/reg.h; the test program left a byte pattern in the general purpose ones.
    ld, core = load_core("x86_64", "elfcore_freebsd_amd64.core")

    assert core.threads == [0]
    registers = core.thread_registers()
    assert registers["rip"] == 0x20242B
    assert registers["rsp"] == 0x2B2A292827262524
    assert registers["rax"] == 0x2726252423222120
    assert registers["rdi"] == 0x2E2D2C2B2A292827
    assert registers["rsi"] == 0x2D2C2B2A29282726
    assert registers["rbp"] == 0x2C2B2A2928272625
    assert registers["r8"] == 0x2F2E2D2C2B2A2928
    assert registers["r15"] == 0x363534333231302F
    assert registers["cs"] == 0x43
    assert registers["eflags"] == 0x10246
    # the segment bases live in a note of their own, so FreeBSD's register set has no fs_base
    assert "fs_base" not in registers
    assert ld.tls.threads[0].thread_pointer == 0


def test_freebsd_prstatus_i386():
    # struct reg from sys/x86/include/reg.h, in a 104 byte struct prstatus
    _, core = load_core("i386", "elfcore_freebsd_i386.core")

    assert core.threads == [0]
    registers = core.thread_registers()
    assert registers["eip"] == 0x401C6B
    assert registers["esp"] == 0x27262524
    assert registers["eax"] == 0x23222120
    assert registers["edi"] == 0x2A292827
    assert registers["ebp"] == 0x28272625
    assert registers["cs"] == 0x33
    assert registers["eflags"] == 0x10246
    assert registers["gs"] == 0x1B


def test_freebsd_prstatus_aarch64():
    # struct reg from sys/arm64/include/reg.h, in a 320 byte struct prstatus, one per thread
    _, core = load_core("aarch64", "elfcore_freebsd_aarch64.core")

    assert core.threads == [0, 1, 2, 3]
    registers = core.thread_registers()
    assert registers["pc"] == 0x211FC4
    assert registers["sp"] == 0xFFFFBFFFDEA0
    assert registers["x30"] == 0x212074
    assert registers["x29"] == 0xFFFFBFFFDF30
    assert registers["x0"] == 0x1010101
    assert core.thread_registers(2)["pc"] == 0x211FC8
    assert core.thread_registers(2)["x0"] == 0x11111111


def test_netbsd_registers_amd64():
    # NetBSD's NT_PRSTATUS is a struct netbsd_elfcore_procinfo, which holds no registers at all. Those
    # live in one PT_GETREGS note per LWP, named "NetBSD-CORE@<lwpid>" and typed 33 on x86: a struct
    # reg from sys/arch/amd64/include/reg.h.
    ld, core = load_core("x86_64", "elfcore_netbsd_amd64.core")

    # the procinfo note holds no registers, so it must not have contributed a thread of its own
    assert core.threads == [0]
    registers = core.thread_registers()
    assert registers["rip"] == 0x400C47
    assert registers["rsp"] == 0x2B2A292827262524
    assert registers["rax"] == 0x2726252423222120
    assert registers["rdi"] == 0x2E2D2C2B2A292827
    assert registers["rbp"] == 0x2C2B2A2928272625
    assert registers["r15"] == 0x363534333231302F
    assert registers["cs"] == 0x47
    assert registers["eflags"] == 0x10212
    assert "fs_base" not in registers
    assert ld.tls.threads[0].thread_pointer == 0


def test_netbsd_registers_i386():
    # struct reg from sys/arch/i386/include/reg.h, in a PT_GETREGS note typed 33
    _, core = load_core("i386", "elfcore_netbsd_i386.core")

    assert core.threads == [0]
    registers = core.thread_registers()
    assert registers["eip"] == 0x8048955
    assert registers["esp"] == 0x27262524
    assert registers["eax"] == 0x23222120
    assert registers["edi"] == 0x2A292827
    assert registers["ebp"] == 0x28272625
    assert registers["eflags"] == 0x10282
    assert registers["gs"] == 0x8B


def test_netbsd_registers_aarch64():
    # struct reg from sys/arch/aarch64/include/reg.h: r_reg[31], then sp, pc, spsr and tpidr. The note
    # is typed 32 rather than 33, because PT_GETREGS is the first machine-dependent ptrace request on
    # aarch64 and the second on x86.
    _, core = load_core("aarch64", "elfcore_netbsd_aarch64.core")

    assert core.threads == [0]
    registers = core.thread_registers()
    assert registers["pc"] == 0x200100830
    assert registers["sp"] == 0xFFFFFFF98770
    assert registers["x30"] == 0x200100864
    assert registers["x29"] == 0xFFFFFFF98790
    assert registers["x1"] == 0x2F


def test_linux_x86_tls_note():
    # Linux writes every register set other than the general purpose and floating point ones under its
    # own name rather than under CORE, NT_386_TLS among them. A loader that looks for it under CORE
    # never finds it and falls back to guessing the thread's TLS region out of memory.
    ld, core = load_core("i386", "elfcore_linux_i386.core")

    registers = core.thread_registers()
    assert registers["eip"] == 0x80492AB
    assert registers["gs"] == 0x63
    # the GDT entry gs selects, straight out of the note
    assert ld.tls.threads[0].thread_pointer == 0xF7984700


def test_prstatus_abi_mismatch():
    # a Linux x32 core: EM_X86_64 with ELFCLASS32. Its NT_PRSTATUS is 296 bytes, which is neither the
    # 144 of an i386 elf_prstatus nor the 332 of an amd64 one, so the thread is dropped whichever of
    # the two cle resolves the container to. Its NT_AUXV is ELFCLASS32 and reads at four bytes either way.
    ld, core = load_core("x86_64", "elfcore_linux_x32.core")

    # the registers cannot be represented, but the core's memory still loads
    assert core.threads == []
    assert core.thread_registers() == {}
    assert ld.memory.load(0x400400, 8).hex() == "4883ec084883c408"

    # the auxv note is an ELFCLASS32 one whatever e_machine says, so its entries are two four-byte
    # words; read at eight the note runs out mid-entry and AT_HWCAP's CPUID word becomes nonsense
    assert core.auxv["AT_PHENT"] == 0x20  # sizeof(Elf32_Phdr)
    assert core.auxv["AT_HWCAP"] == 0xBFEBFBFF
    assert core.auxv["AT_EXECFN"] == b"./a.out"


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
