
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))


def test_blob_0():

    BASE_ADDR = 0x8000000
    ENTRYPOINT = 0x8001337

    blob_file = os.path.join(TEST_BASE, 'tests', 'i386', 'all')
    ld = cle.Loader(blob_file, main_opts={
        'backend': 'blob',
        'custom_base_addr': BASE_ADDR,
        'custom_entry_point': ENTRYPOINT,
        'custom_arch': "ARM",
    })

    nose.tools.assert_equal(ld.main_object.linked_base, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.mapped_base, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.min_addr, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.entry, ENTRYPOINT)


def test_blob_1():

    # Make sure the base address behaves as expected regardless of whether custom_offset is specified or not.

    BASE_ADDR = 0x8000000
    ENTRYPOINT = 0x8001337

    blob_file = os.path.join(TEST_BASE, 'tests', 'i386', 'all')
    ld = cle.Loader(blob_file, main_opts={
        'backend': 'blob',
        'custom_base_addr': BASE_ADDR,
        'custom_entry_point': ENTRYPOINT,
        'custom_arch': "ARM",
        'custom_offset': 0x200,
    })

    nose.tools.assert_equal(ld.main_object.linked_base, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.mapped_base, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.min_addr, BASE_ADDR)
    nose.tools.assert_equal(ld.main_object.entry, ENTRYPOINT)


if __name__ == "__main__":
    test_blob_0()
    test_blob_1()
