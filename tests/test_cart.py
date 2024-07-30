from __future__ import annotations

import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_cart_pe():
    cartfile = os.path.join(
        TEST_BASE,
        "tests",
        "x86_64",
        "windows",
        "6f289eb8c8cd826525d79b195b1cf187df509d56120427b10ea3fb1b4db1b7b5.sys.cart",
    )
    ld = cle.Loader(
        cartfile, auto_load_libs=False, main_opts={"arc4_key": b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"}
    )
    assert isinstance(ld.main_object, cle.PE)
    assert ld.main_object.os == "windows"


def test_cart_elf():
    cartfile = os.path.join(
        TEST_BASE,
        "tests",
        "x86_64",
        "1after909.cart",
    )
    ld = cle.Loader(
        cartfile, auto_load_libs=False, main_opts={"arc4_key": b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00"}
    )
    assert isinstance(ld.main_object, cle.ELF)
    assert ld.main_object.os == "UNIX - System V"


def test_cart_elf_with_load_options():
    cartfile = os.path.join(
        TEST_BASE,
        "tests",
        "x86_64",
        "1after909.cart",
    )
    unpacked_name = cle.backends.CARTFile.get_unpacked_name(cartfile)
    ld = cle.Loader(
        cartfile,
        auto_load_libs=False,
        main_opts={
            "arc4_key": b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        },
        lib_opts={
            unpacked_name: {
                "base_addr": 0x500000,
            }
        },
    )
    assert isinstance(ld.main_object, cle.ELF)
    assert ld.main_object.mapped_base == 0x500000


def test_cart_blob_with_load_options():
    cartfile = os.path.join(
        TEST_BASE,
        "tests",
        "x86_64",
        "1after909.cart",
    )
    unpacked_name = cle.backends.CARTFile.get_unpacked_name(cartfile)
    ld = cle.Loader(
        cartfile,
        auto_load_libs=False,
        main_opts={
            "arc4_key": b"\x02\xf53asdf\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        },
        lib_opts={
            unpacked_name: {
                "backend": cle.backends.Blob,
                "arch": "amd64",
                "entry_point": 0x600000,
                "base_addr": 0x500000,
            }
        },
    )
    assert isinstance(ld.main_object, cle.Blob)
    assert ld.main_object.mapped_base == 0x500000
    assert ld.main_object.entry == 0x600000


if __name__ == "__main__":
    test_cart_pe()
    test_cart_elf()
    test_cart_elf_with_load_options()
    test_cart_blob_with_load_options()
