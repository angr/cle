import os
import shutil
import tempfile

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_runpath():
    tempdir = tempfile.mkdtemp()
    try:
        runpath_file = os.path.join(TEST_BASE, "tests", "x86_64", "runpath")
        relocated_file = os.path.join(tempdir, "runpath")

        expected_libs = []
        os.mkdir(os.path.join(tempdir, "lib"))
        for lib in ["libc.so.6", "ld-linux-x86-64.so.2"]:
            src = os.path.join(TEST_BASE, "tests", "x86_64", lib)
            dst = os.path.join(tempdir, "lib", lib)
            expected_libs.append(os.path.realpath(dst))
            shutil.copy(src, dst)

        shutil.copy(runpath_file, relocated_file)

        loader = cle.Loader(relocated_file, except_missing_libs=True)
        assert loader.all_objects[1].binary in expected_libs
        assert loader.all_objects[2].binary in expected_libs
    finally:
        shutil.rmtree(tempdir)


if __name__ == "__main__":
    test_runpath()
