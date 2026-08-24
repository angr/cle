from __future__ import annotations

import os
import tempfile
import zipfile

import pytest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))
# The bytecode of the android1 test APK, which is also a valid input on its own.
APK = os.path.join(TEST_BASE, "tests", "java", "android1.apk")


def extract_classes_dex(target_dir: str) -> str:
    with zipfile.ZipFile(APK) as archive:
        return archive.extract("classes.dex", path=target_dir)


def test_dex_needs_an_android_sdk():
    with tempfile.TemporaryDirectory() as target_dir:
        dex = extract_classes_dex(target_dir)
        with pytest.raises(cle.CLEError) as caught:
            cle.Loader(dex, auto_load_libs=False)
    assert "android_sdk" in str(caught.value)


def test_dex_needs_an_api_version():
    with tempfile.TemporaryDirectory() as target_dir:
        dex = extract_classes_dex(target_dir)
        with pytest.raises(cle.CLEError) as caught:
            cle.Loader(dex, auto_load_libs=False, main_opts={"android_sdk": target_dir})
    assert "android_api_version" in str(caught.value)
