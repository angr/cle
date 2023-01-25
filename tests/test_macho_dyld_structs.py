from cle.backends.macho.structs import (
    ChainedFixupPointerOnDisk,
    Generic64,
    dyld_chained_import,
    dyld_chained_ptr_64_rebase,
)


def test_parsing_simple():
    """
    basically the same tests as test_struct_bitfield_simple from test_memview.py
    :return:
    """
    data = [
        (b"\x0e\x02\x00\x00", (14, 0, 1)),
        (b"\x14T\x00\x00", (20, 0, 42)),
        (b"\x04\n\x01\x00", (4, 0, 133)),
        (b"\x04j\x01\x00", (4, 0, 181)),
        (b"\x04\xa2\x01\x00", (4, 0, 209)),
        (b"\x04\xf4\x01\x00", (4, 0, 250)),
        (b"\x04\\\x02\x00", (4, 0, 302)),
        (b"\x04\x98\x02\x00", (4, 0, 332)),
        (b"\x04\xe0\x02\x00", (4, 0, 368)),
        (b"\x04\x1e\x03\x00", (4, 0, 399)),
    ]
    for b, (lib_ordinal, weak_import, name_offset) in data:
        struct = dyld_chained_import.from_buffer_copy(b)
        assert struct.lib_ordinal == lib_ordinal
        assert struct.weak_import == weak_import
        assert struct.name_offset == name_offset


def test_parsing_complex():
    """
    basically the same tests as test_struct_bitfield_complex from test_memview.py
    :return:
    """
    data = b"\xb3\xc7\xe9|\xad\xd7\xee$"

    # Check that parsing the struct directly works
    struct = dyld_chained_ptr_64_rebase.from_buffer_copy(data)
    assert struct.target == 0xD7CE9C7B3
    assert struct.high8 == 0x7A
    assert struct.next == 0x49D
    assert struct.bind == 0

    # Test that the Generic64 union works
    generic_union = Generic64.from_buffer_copy(data)

    struct = generic_union.rebase
    assert struct.target == 0xD7CE9C7B3
    assert struct.high8 == 0x7A
    assert struct.next == 0x49D
    assert struct.bind == 0

    chained_union = ChainedFixupPointerOnDisk.from_buffer_copy(data)
    struct = chained_union.generic64.rebase
    assert struct.target == 0xD7CE9C7B3
    assert struct.high8 == 0x7A
    assert struct.next == 0x49D
    assert struct.bind == 0


if __name__ == "__main__":
    test_parsing_simple()
    test_parsing_complex()
