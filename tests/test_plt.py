import os
import nose
import subprocess
import pickle
import cle

TESTS_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries')
TESTS_ARCHES = ['i386/libc.so.6', 'i386/fauxware', 'x86_64/libc.so.6', 'x86_64/fauxware', 'armel/libc.so.6', 'armel/fauxware', 'armhf/libc.so.6', 'ppc/libc.so.6', 'ppc/fauxware', 'mips/libc.so.6', 'mips/fauxware', 'mips64/libc.so.6', 'mips64/test_arrays', 'aarch64/libc.so.6', 'aarch64/test_arrays']

def check_plt_entries(filename):
    real_filename = os.path.join(TESTS_BASE, 'tests', filename)
    ld = cle.Loader(real_filename, auto_load_libs=False)

    if filename == 'ppc/libc.so.6':
        # objdump can't find PLT stubs for this...
        nose.tools.assert_not_equal(ld.main_bin._plt, {})
        sorted_keys = sorted(ld.main_bin._plt.values())
        diffs = [y - x for x, y in zip(sorted_keys, sorted_keys[1:])]
        nose.tools.assert_equal(diffs, [4]*len(diffs))
        return

    if filename == 'mips/libc.so.6':
        nose.tools.assert_in('__tls_get_addr', ld.main_bin._plt)
        nose.tools.assert_equal(ld.main_bin._plt['__tls_get_addr'], 1331168)
        return

    if filename == 'mips/fauxware':
        nose.tools.assert_equal(ld.main_bin._plt, {'puts': 4197264, 'read': 4197232, '__libc_start_main': 4197312, 'printf': 4197248, 'exit': 4197280, 'open': 4197296, 'strcmp': 4197216})
        return

    if filename == 'mips64/libc.so.6':
        nose.tools.assert_equal(ld.main_bin._plt, {'__tls_get_addr': 1458432, '_dl_find_dso_for_object': 1458448})
        return

    if filename == 'mips64/test_arrays':
        nose.tools.assert_equal(ld.main_bin._plt, {'__libc_start_main': 4831841456, 'puts': 4831841440})
        return

    p1 = subprocess.Popen(['objdump', '-d', real_filename], stdout=subprocess.PIPE)
    p2 = subprocess.Popen(['grep', '@plt>:'], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    dat, _ = p2.communicate()
    lines = dat.strip().split('\n')

    ideal_plt = {}
    for line in lines:
        addr, ident = line.split()
        addr = int(addr, 16)
        name = ident.split('@')[0].strip('<')
        if '*' in name or name == '__gmon_start__':
            continue
        ideal_plt[name] = addr

    ld.main_bin._plt.pop('__gmon_start__', None)

    if filename == 'armhf/libc.so.6':
        # objdump does these cases wrong as far as I can tell?
        # or maybe not wrong just... different
        # there's a prefix to this stub that jumps out of thumb mode
        # cle finds the arm stub, objdump finds the thumb prefix
        ideal_plt['free'] += 4
        ideal_plt['malloc'] += 4
    nose.tools.assert_equal(ideal_plt, ld.main_bin._plt)

def test_plt():
    for filename in TESTS_ARCHES:
        yield check_plt_entries, filename

if __name__ == '__main__':
    for f, a in test_plt():
        print a
        f(a)
