import os
import subprocess
import pickle

import nose
import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries'))
TESTS_ARCHES = [os.path.join('i386', 'libc.so.6'),
                os.path.join('i386', 'fauxware'),
                os.path.join('x86_64', 'libc.so.6'),
                os.path.join('x86_64', 'fauxware'),
                os.path.join('x86_64', 'true'),
                os.path.join('x86_64', 'welcome'),
                os.path.join('x86_64', 'simple_overflow_nopie'),
                os.path.join('armel', 'libc.so.6'),
                os.path.join('armel', 'fauxware'),
                os.path.join('armel', 'helloworld'),
                os.path.join('armhf', 'libc.so.6'),
                os.path.join('ppc', 'libc.so.6'),
                os.path.join('ppc', 'fauxware'),
                os.path.join('mips', 'libc.so.6'),
                os.path.join('mips', 'fauxware'),
                os.path.join('mips64', 'libc.so.6'),
                os.path.join('mips64', 'test_arrays'),
                os.path.join('aarch64', 'libc.so.6'),
                os.path.join('aarch64', 'test_arrays'),
                ]

def check_plt_entries(filename):
    real_filename = os.path.join(TESTS_BASE, 'tests', filename)
    ld = cle.Loader(real_filename, auto_load_libs=False, main_opts={'base_addr': 0})

    if filename == os.path.join('ppc', 'libc.so.6'):
        # objdump can't find PLT stubs for this...
        nose.tools.assert_not_equal(ld.main_object._plt, {})
        sorted_keys = sorted(ld.main_object._plt.values())
        diffs = [y - x for x, y in zip(sorted_keys, sorted_keys[1:])]
        nose.tools.assert_equal(diffs, [4]*len(diffs))
        return

    # all our mips samples have no PLT, just resolver stubs
    if filename.startswith('mips'):
        nose.tools.assert_equal(ld.main_object.plt, {})
        return

    if filename == os.path.join('armel', 'helloworld'):
        nose.tools.assert_equal(ld.main_object.plt, {'printf': 0x102e0, '__libc_start_main': 0x102ec,
                                                   '__gmon_start__': 0x102f8, 'abort': 0x10304
                                                   }
                                )
        return

    if filename == os.path.join('x86_64', 'true'):
        nose.tools.assert_equal(ld.main_object.plt, {u'__uflow': 0x1440, u'getenv': 0x1448, u'free': 0x1450, u'abort': 0x1458, u'__errno_location': 0x1460, u'strncmp': 0x1468, u'_exit': 0x1470, u'__fpending': 0x1478, u'textdomain': 0x1480, u'fclose': 0x1488, u'bindtextdomain': 0x1490, u'dcgettext': 0x1498, u'__ctype_get_mb_cur_max': 0x14a0, u'strlen': 0x14a8, u'__stack_chk_fail': 0x14b0, u'mbrtowc': 0x14b8, u'strrchr': 0x14c0, u'lseek': 0x14c8, u'memset': 0x14d0, u'fscanf': 0x14d8, u'close': 0x14e0, u'memcmp': 0x14e8, u'fputs_unlocked': 0x14f0, u'calloc': 0x14f8, u'strcmp': 0x1500, u'memcpy': 0x1508, u'fileno': 0x1510, u'malloc': 0x1518, u'fflush': 0x1520, u'nl_langinfo': 0x1528, u'ungetc': 0x1530, u'__freading': 0x1538, u'realloc': 0x1540, u'fdopen': 0x1548, u'setlocale': 0x1550, u'__printf_chk': 0x1558, u'error': 0x1560, u'open': 0x1568, u'fseeko': 0x1570, u'__cxa_atexit': 0x1578, u'exit': 0x1580, u'fwrite': 0x1588, u'__fprintf_chk': 0x1590, u'mbsinit': 0x1598, u'iswprint': 0x15a0, u'__cxa_finalize': 0x15a8, u'__ctype_b_loc': 0x15b0})
        return

    ld.main_object._plt.pop('__gmon_start__', None)

    replaced_filename = filename.replace('\\', '/')
    if replaced_filename not in PLT_CACHE:
        p1 = subprocess.Popen(['objdump', '-d', real_filename], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(['grep', '@plt>:'], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()
        dat, _ = p2.communicate()
        lines = dat.decode().strip().split('\n')

        ideal_plt = {}
        for line in lines:
           addr, ident = line.split()
           addr = int(addr, 16)
           name = ident.split('@')[0].strip('<')
           if '*' in name or name == '__gmon_start__':
               continue
           ideal_plt[name] = addr

        if filename == os.path.join('armhf', 'libc.so.6'):
           # objdump does these cases wrong as far as I can tell?
           # or maybe not wrong just... different
           # there's a prefix to this stub that jumps out of thumb mode
           # cle finds the arm stub, objdump finds the thumb prefix
           ideal_plt['free'] += 4
           ideal_plt['malloc'] += 4
        print("Regenerated ideal PLT for %s as %s", filename, ideal_plt)
        PLT_CACHE[filename.replace('\\', '/')] = ideal_plt

    ideal_plt = PLT_CACHE[replaced_filename]
    nose.tools.assert_equal(ideal_plt, ld.main_object.plt)

#PLT_CACHE = {}
with open(os.path.join(TESTS_BASE, 'tests_data', 'objdump-grep-plt.p'), 'rb') as fp:
    PLT_CACHE = pickle.load(fp)

def test_plt():
    for filename in TESTS_ARCHES:
        yield check_plt_entries, filename

def test_plt_full_relro():
    ld = cle.Loader(os.path.join(TESTS_BASE, 'tests/i386/full-relro.bin'), main_opts={'base_addr': 0x400000})
    assert ld.main_object.plt == {'__libc_start_main': 0x400390}

if __name__ == '__main__':
    for f, a in test_plt():
        print(a)
        f(a)
    pickle.dump(PLT_CACHE, open(os.path.join(TESTS_BASE, 'tests_data', 'objdump-grep-plt.p'), 'wb'))
