import os

import cle

test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    os.path.join("..", "..", "binaries", "tests"),
)


def test_gcc_4():
    filename = os.path.join(test_location, "x86_64", "test_arrays")
    ld = cle.Loader(filename, auto_load_libs=False)
    assert ld.main_object.compiler == ("gcc", "4.8.2-19ubuntu1")


def test_clang_6():
    filename = os.path.join(test_location, "x86_64", "hello_clang")
    ld = cle.Loader(filename, auto_load_libs=False)
    assert ld.main_object.compiler == ("clang", "6.0.0-1ubuntu2")


if __name__ == "__main__":
    test_gcc_4()
    test_clang_6()
