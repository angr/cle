import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_cart():
    cartfile = os.path.join(
        TEST_BASE,
        "tests",
        "x86_64",
        "windows",
        "6f289eb8c8cd826525d79b195b1cf187df509d56120427b10ea3fb1b4db1b7b5.sys.cart",
    )
    ld = cle.Loader(cartfile, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.PE)
    assert ld.main_object.os == "windows"


if __name__ == "__main__":
    test_cart()
