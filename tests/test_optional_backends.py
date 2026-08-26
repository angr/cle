from __future__ import annotations

import subprocess
import sys
import unittest


@unittest.skipIf(sys.platform == "emscripten", "subprocesses are unavailable in Pyodide")
def test_import_without_uefi_firmware():
    script = """
import sys

sys.modules["uefi_firmware"] = None

import cle
from cle.backends import ALL_BACKENDS

assert "uefi" in ALL_BACKENDS
"""
    subprocess.run([sys.executable, "-c", script], check=True)
