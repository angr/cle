import os
import nose
#import subprocess
import pickle
import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          os.path.join('..', '..', 'binaries'))
TESTS_ARCHES = [os.path.join('i386', 'libc.so.6'),
                os.path.join('i386', 'fauxware'),
                os.path.join('x86_64', 'libc.so.6'),
                os.path.join('x86_64', 'fauxware'),
                os.path.join('x86_64', 'true'),
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
    ld = cle.Loader(real_filename, auto_load_libs=False, main_opts={'custom_base_addr': 0})

    if filename == os.path.join('ppc', 'libc.so.6'):
        # objdump can't find PLT stubs for this...
        nose.tools.assert_not_equal(ld.main_object._plt, {})
        sorted_keys = sorted(ld.main_object._plt.values())
        diffs = [y - x for x, y in zip(sorted_keys, sorted_keys[1:])]
        nose.tools.assert_equal(diffs, [4]*len(diffs))
        return

    if filename == os.path.join('mips', 'libc.so.6'):
        nose.tools.assert_in('__tls_get_addr', ld.main_object._plt)
        nose.tools.assert_equal(ld.main_object.plt['__tls_get_addr'], 1331168)
        return

    if filename == os.path.join('mips', 'fauxware'):
        nose.tools.assert_equal(ld.main_object.plt, {'puts': 4197264, 'read': 4197232, '__libc_start_main': 4197312, 'printf': 4197248, 'exit': 4197280, 'open': 4197296, 'strcmp': 4197216})
        return

    if filename == os.path.join('mips64', 'libc.so.6'):
        nose.tools.assert_equal(ld.main_object.plt, {'__tls_get_addr': 1458432, '_dl_find_dso_for_object': 1458448})
        return

    if filename == os.path.join('mips64', 'test_arrays'):
        nose.tools.assert_equal(ld.main_object.plt, {'__libc_start_main': 4831841456, 'puts': 4831841440})
        return

    if filename == os.path.join('armel', 'helloworld'):
        nose.tools.assert_equal(ld.main_object.plt, {'printf': 0x102e0, '__libc_start_main': 0x102ec,
                                                   '__gmon_start__': 0x102f8, 'abort': 0x10304
                                                   }
                                )
        return

    if filename == os.path.join('x86_64', 'true'):
        nose.tools.assert_equal(ld.main_object.plt, {u'__uflow': 0x1440, u'getenv': 0x1448L, u'free': 0x1450L, u'abort': 0x1458L, u'__errno_location': 0x1460L, u'strncmp': 0x1468L, u'_exit': 0x1470L, u'__fpending': 0x1478L, u'textdomain': 0x1480L, u'fclose': 0x1488L, u'bindtextdomain': 0x1490L, u'dcgettext': 0x1498L, u'__ctype_get_mb_cur_max': 0x14a0L, u'strlen': 0x14a8L, u'__stack_chk_fail': 0x14b0L, u'mbrtowc': 0x14b8L, u'strrchr': 0x14c0L, u'lseek': 0x14c8L, u'memset': 0x14d0L, u'fscanf': 0x14d8L, u'close': 0x14e0L, u'memcmp': 0x14e8L, u'fputs_unlocked': 0x14f0L, u'calloc': 0x14f8L, u'strcmp': 0x1500L, u'memcpy': 0x1508L, u'fileno': 0x1510L, u'malloc': 0x1518L, u'fflush': 0x1520L, u'nl_langinfo': 0x1528L, u'ungetc': 0x1530L, u'__freading': 0x1538L, u'realloc': 0x1540L, u'fdopen': 0x1548L, u'setlocale': 0x1550L, u'__printf_chk': 0x1558L, u'error': 0x1560L, u'open': 0x1568L, u'fseeko': 0x1570L, u'__cxa_atexit': 0x1578L, u'exit': 0x1580L, u'fwrite': 0x1588L, u'__fprintf_chk': 0x1590L, u'mbsinit': 0x1598L, u'iswprint': 0x15a0L, u'__cxa_finalize': 0x15a8L, u'__ctype_b_loc': 0x15b0L})
        return

    ld.main_object._plt.pop('__gmon_start__', None)

    #p1 = subprocess.Popen(['objdump', '-d', real_filename], stdout=subprocess.PIPE)
    #p2 = subprocess.Popen(['grep', '@plt>:'], stdin=p1.stdout, stdout=subprocess.PIPE)
    #p1.stdout.close()
    #dat, _ = p2.communicate()
    #lines = dat.strip().split('\n')

    #ideal_plt = {}
    #for line in lines:
    #    addr, ident = line.split()
    #    addr = int(addr, 16)
    #    name = ident.split('@')[0].strip('<')
    #    if '*' in name or name == '__gmon_start__':
    #        continue
    #    ideal_plt[name] = addr

    #if filename == os.path.join('armhf', 'libc.so.6'):
    #    # objdump does these cases wrong as far as I can tell?
    #    # or maybe not wrong just... different
    #    # there's a prefix to this stub that jumps out of thumb mode
    #    # cle finds the arm stub, objdump finds the thumb prefix
    #    ideal_plt['free'] += 4
    #    ideal_plt['malloc'] += 4
    #PLT_CACHE[filename.replace('\\', '/')] = ideal_plt
    ideal_plt = PLT_CACHE[filename.replace('\\', '/')]
    nose.tools.assert_equal(ideal_plt, ld.main_object.plt)

PLT_CACHE = {}
PLT_CACHE = pickle.load(open(os.path.join(TESTS_BASE, 'tests_data', 'objdump-grep-plt.p'), 'rb'))

def test_plt():
    for filename in TESTS_ARCHES:
        yield check_plt_entries, filename

if __name__ == '__main__':
    for f, a in test_plt():
        print a
        f(a)
    #pickle.dump(PLT_CACHE, open(os.path.join(TESTS_BASE, 'tests_data', 'objdump-grep-plt.p'), 'wb'))
