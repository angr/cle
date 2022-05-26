import os
import cle
import logging

test_location = os.path.dirname(os.path.realpath(__file__))
bins_location = os.path.join(test_location, "../../binaries/tests/i386")


def test_preload():
    l = cle.Loader(
        os.path.join(bins_location, "test_preload"),
        auto_load_libs=True,
        preload_libs=[os.path.join(bins_location, "strcpy_lib.so")],
    )
    s = l.find_symbol("strcpy")
    assert "strcpy_lib.so" in s.owner.binary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_preload()
