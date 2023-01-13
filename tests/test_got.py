import os
import unittest

import cle


class TestGOT(unittest.TestCase):
    test_location = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        os.path.join("..", "..", "binaries", "tests"),
    )

    def test_ppc(self):
        libc = os.path.join(self.test_location, "ppc", "libc.so.6")
        ld = cle.Loader(libc, auto_load_libs=True, main_opts={"base_addr": 0})
        # This tests the relocation of _rtld_global_ro in ppc libc6.
        # This relocation is of type 20, and relocates a non-local symbol
        relocated = ld.memory.unpack_word(0x18ACE4)
        assert relocated % 0x1000 == 0xF666E320 % 0x1000

    def test_mipsel(self):
        ping = os.path.join(self.test_location, "mipsel", "darpa_ping")
        skip = ["libgcc_s.so.1", "libresolv.so.0"]
        ld = cle.Loader(ping, skip_libs=skip)
        dep = set(ld._satisfied_deps)
        loadedlibs = set(ld.shared_objects)

        # 1) check dependencies and loaded binaries
        self.assertTrue(dep.issuperset({"libresolv.so.0", "libgcc_s.so.1", "libc.so.6", "ld.so.1"}))
        self.assertTrue(loadedlibs.issuperset({"libc.so.6", "ld.so.1"}))

        # 2) Check GOT slot containts the right address
        # Cle: 4494036
        # got = ld.find_symbol_got_entry('__uClibc_main')
        # addr = ld.memory.unpack_word(got)
        # self.assertEqual(addr, sproc_addr)
        # TODO: Get the right version of uClibc and devise a test that doesn't use angr

        ioctl = next(ld.find_relevant_relocations("ioctl"))
        setsockopt = next(ld.find_relevant_relocations("setsockopt"))

        self.assertEqual(ioctl.rebased_addr, 4494300)
        self.assertEqual(setsockopt.rebased_addr, 4494112)
