from __future__ import annotations

import os
import unittest
from unittest import TestCase

import archinfo

import cle

try:
    import pypcode
except ImportError:
    pypcode = None

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))


class TestTlsResiliency(TestCase):
    @staticmethod
    def test_tls_pe_incorrect_tls_data_start():
        p = os.path.join(test_location, "i386", "windows", "2.exe")
        path_ld = cle.Loader(p, auto_load_libs=True)
        assert path_ld is not None
        th = path_ld.tls.new_thread()
        assert th is not None

    @staticmethod
    @unittest.skipIf(pypcode is None, "pypcode not installed")
    def test_tls_24bit_arch():
        # isqrt_atmega128.o is an ATmega128 object whose e_flags name the extended-address AVR
        # variant, which Ghidra's AVR8 opinion file maps to avr8:LE:16:extended -- a language whose
        # word is three bytes wide despite the 16 in its name. cle's own opinion matching compares
        # the opinion's secondary constraint against e_type instead of e_flags, so it picks
        # avr8:LE:16:default for every EM_AVR ELF; name the language here rather than wait for that
        # to be fixed. Setting up the ELF TLS header writes the DTV pointer one word at a time.
        p = os.path.join(test_location, "avr", "isqrt_atmega128.o")
        ld = cle.Loader(
            p,
            main_opts={"arch": archinfo.ArchPcode("avr8:LE:16:extended")},
            auto_load_libs=False,
        )
        arch = ld.main_object.arch
        assert arch.bits == 24

        thread = ld.tls.new_thread()
        assert thread is not None

        # the DTV pointer is the write that fails, so read it back rather than trusting the load. It is
        # relocated, so what lands in memory is the address of the DTV rather than its offset -- compare
        # against that instead of against the offset alone, which would pin wherever the loader chose to
        # put the thread.
        elf_tls = arch.elf_tls
        assert elf_tls is not None and elf_tls.dtv_offsets
        for offset in elf_tls.dtv_offsets:
            assert thread.memory.unpack_word(offset + thread.tcb_offset) == thread.mapped_base + thread.dtv_offset


if __name__ == "__main__":
    unittest.main()
