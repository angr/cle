from __future__ import annotations

import io
import os
import struct
import unittest
from unittest import TestCase

import cle

try:
    import pypcode
except ImportError:
    pypcode = None

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries", "tests"))

EM_DSPIC30F = 118


def minimal_elf(e_machine: int) -> bytes:
    """
    Build a minimal ELF32 LE executable with one PT_LOAD segment and no sections.
    """
    ehsize, phentsize = 52, 32
    contents = bytes(16)
    offset = ehsize + phentsize
    vaddr = 0x400000 + offset
    ehdr = b"\x7fELF" + bytes([1, 1, 1, 0, 0]) + bytes(7)
    ehdr += struct.pack("<HHIIIIIHHHHHH", 2, e_machine, 1, vaddr, ehsize, 0, 0, ehsize, phentsize, 1, 40, 0, 0)
    phdr = struct.pack("<IIIIIIII", 1, offset, vaddr, vaddr, len(contents), len(contents), 5, 0x1000)
    return ehdr + phdr + contents


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
        # EM_DSPIC30F is autodetected as dsPIC30F:LE:24:default, whose word is three bytes wide.
        # Setting up the ELF TLS header writes the DTV pointer one word at a time.
        ld = cle.Loader(io.BytesIO(minimal_elf(EM_DSPIC30F)), auto_load_libs=False)
        arch = ld.main_object.arch
        assert arch.bits == 24

        thread = ld.tls.new_thread()
        assert thread is not None

        # the DTV pointer is the write that fails, so read it back rather than trusting the load
        elf_tls = arch.elf_tls
        assert elf_tls is not None and elf_tls.dtv_offsets
        for offset in elf_tls.dtv_offsets:
            assert thread.memory.unpack_word(offset + thread.tcb_offset) == thread.dtv_offset


if __name__ == "__main__":
    unittest.main()
