import nose
import cle
import os

def test_relocated():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests/i386/fauxware')
    shared = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests/i386/prelinked')
    ld = cle.Loader(filename, custom_ld_path=[shared])
    nose.tools.assert_equal(ld.main_object.mapped_base, 0x8048000)
    nose.tools.assert_sequence_equal(
        map(lambda x: x.mapped_base, ld.all_elf_objects),
        [0x8048000, 0x9000000, 0xA000000]
    )

def test_first_fit():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests/x86_64/cfg_0')

    ld = cle.Loader(filename)
    nose.tools.assert_less(ld.main_object.mapped_base, ld.shared_objects['libc.so.6'].mapped_base)
    nose.tools.assert_less(ld.shared_objects['libc.so.6'].mapped_base, ld.shared_objects['ld-linux-x86-64.so.2'].mapped_base)

    #[<ELF Object cfg_0, maps [0x400000:0x601047]>,
    # <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
    # <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>,
    # <ELFTLSObj Object ##cle_tls##, maps [0x3000000:0x3030000]>]

    ld = cle.Loader(filename, lib_opts={'libc.so.6': {'custom_base_addr': 0x1234000}})
    nose.tools.assert_less(ld.main_object.mapped_base, ld.shared_objects['ld-linux-x86-64.so.2'].mapped_base)
    nose.tools.assert_less(ld.shared_objects['ld-linux-x86-64.so.2'].mapped_base, ld.shared_objects['libc.so.6'].mapped_base)

    #[<ELF Object cfg_0, maps [0x400000:0x601047]>,
    # <ELF Object ld-linux-x86-64.so.2, maps [0x1000000:0x12241c7]>,
    # <ELF Object libc.so.6, maps [0x1234000:0x15f82bf]>,
    # <ELFTLSObj Object ##cle_tls##, maps [0x2000000:0x2030000]>]

    ld = cle.Loader(filename, lib_opts={'libc.so.6': {'custom_base_addr': 0x1234000}, 'ld-linux-x86-64.so.2': {'custom_base_addr': 0}})
    nose.tools.assert_less(ld.shared_objects['ld-linux-x86-64.so.2'].mapped_base, ld.main_object.mapped_base)
    nose.tools.assert_less(ld.main_object.mapped_base, ld.shared_objects['libc.so.6'].mapped_base)

    #[<ELF Object ld-linux-x86-64.so.2, maps [0x0:0x2241c7]>,
    # <ELF Object cfg_0, maps [0x400000:0x601047]>,
    # <ELFTLSObj Object ##cle_tls##, maps [0x1000000:0x1030000]>,
    # <ELF Object libc.so.6, maps [0x1234000:0x15f82bf]>]


if __name__ == '__main__':
    test_relocated()
