import nose
import cle
import os


def test_relocated():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests/i386/fauxware')
    shared = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests/i386/prelinked')
    ld = cle.Loader(filename, custom_ld_path=[shared])
    nose.tools.assert_equal(ld.main_bin.mapped_base, 0x8048000)
    nose.tools.assert_sequence_equal(
        map(lambda x: x.mapped_base, ld.all_elf_objects),
        [0x8048000, 0x9000000, 0xA000000]
    )


if __name__ == '__main__':
    test_relocated()
