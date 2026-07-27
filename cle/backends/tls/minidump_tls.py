from __future__ import annotations

import archinfo

from cle.backends.tls.tls_object import ThreadManager


class MinidumpThreadManager(ThreadManager):
    def __init__(self, loader, arch, **kwargs):  # pylint: disable=unused-argument
        self.loader = loader
        self.arch = arch
        self.threads = []
        for tid in loader.main_object.threads:
            try:
                self.threads.append(MinidumpThread(loader, arch, loader.main_object.thread_registers(tid)))
            except KeyError:
                # Small minidumps often preserve register contexts without the TEB or TLS pointer pages.
                pass
        self.modules = []  # ???

    def new_thread(self, insert=False):  # pylint: disable=no-self-use
        raise TypeError("Cannot create new threads from a minidump file... for now")

    def register_object(self, obj):
        pass


class MinidumpThread:
    def __init__(self, loader, arch: archinfo.Arch, registers):
        self.loader = loader
        self.arch = arch
        self._registers = registers
        if arch.name == "AMD64":
            self.teb = registers["gs_const"]
            self.thread_pointer = loader.main_object.memory.unpack_word(self.teb + 0x58)
        elif arch.name == "X86":
            self.teb = registers["fs"]
            self.thread_pointer = loader.main_object.memory.unpack_word(self.teb + 0x2C)

        self.user_thread_pointer = self.thread_pointer

    def get_tls_data_addr(self, tls_idx):
        return self.loader.memory.unpack_word(self.thread_pointer + tls_idx * self.arch.bytes)
