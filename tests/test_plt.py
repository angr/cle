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
