import os
import pickle
import subprocess
import unittest

import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

with open(os.path.join(TESTS_BASE, "tests_data", "objdump-grep-plt.p"), "rb") as fp:
    PLT_CACHE = pickle.load(fp)


class TestCheckPltEntries(unittest.TestCase):
    def _check_plt_entries(self, filename):
        real_filename = os.path.join(TESTS_BASE, "tests", filename)
        ld = cle.Loader(real_filename, auto_load_libs=False, main_opts={"base_addr": 0})

        if filename == os.path.join("ppc", "libc.so.6"):
            # objdump can't find PLT stubs for this...
            self.assertNotEqual(ld.main_object._plt, {})
            sorted_keys = sorted(ld.main_object._plt.values())
            diffs = [y - x for x, y in zip(sorted_keys, sorted_keys[1:])]
            self.assertEqual(diffs, [4] * len(diffs))
            return

        # all our mips samples have no PLT, just resolver stubs
        if filename.startswith("mips"):
            self.assertEqual(ld.main_object.plt, {})
            return

        if filename == os.path.join("armel", "helloworld"):
            self.assertEqual(
                ld.main_object.plt,
                {"printf": 0x102E0, "__libc_start_main": 0x102EC, "__gmon_start__": 0x102F8, "abort": 0x10304},
            )
            return

        if filename == os.path.join("x86_64", "true"):
            self.assertEqual(
                ld.main_object.plt,
                {
                    "__uflow": 0x1440,
                    "getenv": 0x1448,
                    "free": 0x1450,
                    "abort": 0x1458,
                    "__errno_location": 0x1460,
                    "strncmp": 0x1468,
                    "_exit": 0x1470,
                    "__fpending": 0x1478,
                    "textdomain": 0x1480,
                    "fclose": 0x1488,
                    "bindtextdomain": 0x1490,
                    "dcgettext": 0x1498,
                    "__ctype_get_mb_cur_max": 0x14A0,
                    "strlen": 0x14A8,
                    "__stack_chk_fail": 0x14B0,
                    "mbrtowc": 0x14B8,
                    "strrchr": 0x14C0,
                    "lseek": 0x14C8,
                    "memset": 0x14D0,
                    "fscanf": 0x14D8,
                    "close": 0x14E0,
                    "memcmp": 0x14E8,
                    "fputs_unlocked": 0x14F0,
                    "calloc": 0x14F8,
                    "strcmp": 0x1500,
                    "memcpy": 0x1508,
                    "fileno": 0x1510,
                    "malloc": 0x1518,
                    "fflush": 0x1520,
                    "nl_langinfo": 0x1528,
                    "ungetc": 0x1530,
                    "__freading": 0x1538,
                    "realloc": 0x1540,
                    "fdopen": 0x1548,
                    "setlocale": 0x1550,
                    "__printf_chk": 0x1558,
                    "error": 0x1560,
                    "open": 0x1568,
                    "fseeko": 0x1570,
                    "__cxa_atexit": 0x1578,
                    "exit": 0x1580,
                    "fwrite": 0x1588,
                    "__fprintf_chk": 0x1590,
                    "mbsinit": 0x1598,
                    "iswprint": 0x15A0,
                    "__cxa_finalize": 0x15A8,
                    "__ctype_b_loc": 0x15B0,
                },
            )
            return

        ld.main_object._plt.pop("__gmon_start__", None)

        replaced_filename = filename.replace("\\", "/")
        if replaced_filename not in PLT_CACHE:
            p1 = subprocess.Popen(["objdump", "-d", real_filename], stdout=subprocess.PIPE)
            p2 = subprocess.Popen(["grep", "@plt>:"], stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()
            dat, _ = p2.communicate()
            lines = dat.decode().strip().split("\n")

            ideal_plt = {}
            for line in lines:
                addr, ident = line.split()
                addr = int(addr, 16)
                name = ident.split("@")[0].strip("<")
                if "*" in name or name == "__gmon_start__":
                    continue
                ideal_plt[name] = addr

            if filename == os.path.join("armhf", "libc.so.6"):
                # objdump does these cases wrong as far as I can tell?
                # or maybe not wrong just... different
                # there's a prefix to this stub that jumps out of thumb mode
                # cle finds the arm stub, objdump finds the thumb prefix
                ideal_plt["free"] += 4
                ideal_plt["malloc"] += 4
            print("Regenerated ideal PLT for %s as %s", filename, ideal_plt)
            PLT_CACHE[filename.replace("\\", "/")] = ideal_plt

        ideal_plt = PLT_CACHE[replaced_filename]
        self.assertEqual(ideal_plt, ld.main_object.plt)

    def test_i386_libc(self):
        self._check_plt_entries(os.path.join("i386", "libc.so.6"))

    def test_i386_fauxware(self):
        self._check_plt_entries(os.path.join("i386", "fauxware"))

    def test_x86_64_libc(self):
        self._check_plt_entries(os.path.join("x86_64", "libc.so.6"))

    def test_x86_64_fauxware(self):
        self._check_plt_entries(os.path.join("x86_64", "fauxware"))

    def test_x86_64_true(self):
        self._check_plt_entries(os.path.join("x86_64", "true"))

    def test_x86_64_welcome(self):
        self._check_plt_entries(os.path.join("x86_64", "welcome"))

    def test_x86_64_simple_overflow_nopie(self):
        self._check_plt_entries(os.path.join("x86_64", "simple_overflow_nopie"))

    def test_armel_libc(self):
        self._check_plt_entries(os.path.join("armel", "libc.so.6"))

    def test_armel_fauxware(self):
        self._check_plt_entries(os.path.join("armel", "fauxware"))

    def test_armel_helloworld(self):
        self._check_plt_entries(os.path.join("armel", "helloworld"))

    def test_armhf_libc(self):
        self._check_plt_entries(os.path.join("armhf", "libc.so.6"))

    def test_ppc_libc(self):
        self._check_plt_entries(os.path.join("ppc", "libc.so.6"))

    def test_ppc_fauxware(self):
        self._check_plt_entries(os.path.join("ppc", "fauxware"))

    def test_mips_libc(self):
        self._check_plt_entries(os.path.join("mips", "libc.so.6"))

    def test_mips_fauxware(self):
        self._check_plt_entries(os.path.join("mips", "fauxware"))

    def test_mips64_libc(self):
        self._check_plt_entries(os.path.join("mips64", "libc.so.6"))

    def test_aarch64_libc(self):
        self._check_plt_entries(os.path.join("aarch64", "libc.so.6"))

    def test_aarch64_test_arrays(self):
        self._check_plt_entries(os.path.join("aarch64", "test_arrays"))

    def test_mips64_test_arrays(self):
        self._check_plt_entries(os.path.join("mips64", "test_arrays"))


def test_plt_full_relro():
    ld = cle.Loader(
        os.path.join(TESTS_BASE, "tests/i386/full-relro.bin"),
        main_opts={"base_addr": 0x400000},
    )
    assert ld.main_object.plt == {"__libc_start_main": 0x400390}


if __name__ == "__main__":
    unittest.main()
