from __future__ import annotations

import subprocess
import sys


def test_import_without_uefi_firmware():
    script = """
import sys

sys.modules["uefi_firmware"] = None

import cle
from cle.backends import ALL_BACKENDS

assert "uefi" in ALL_BACKENDS
"""
    subprocess.run([sys.executable, "-c", script], check=True)
