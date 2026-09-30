from __future__ import annotations

from pathlib import Path

import cle

GNU_ARCHIVE = (
    Path(__file__).resolve().parents[2]
    / "binaries"
    / "tests_src"
    / "i2c_master_read-nucleol152re"
    / "mbed"
    / "TARGET_NUCLEO_L152RE"
    / "TOOLCHAIN_GCC_ARM"
    / "libmbed.a"
)


def test_gnu_long_name_table():
    archive = cle.Loader(GNU_ARCHIVE, auto_load_libs=False, rebase_granularity=0x1000).main_object

    assert isinstance(archive, cle.StaticArchive)
    assert archive.arch.name == "ARMCortexM"
    children = [child.binary_basename for child in archive.child_objects]
    assert children[:3] == ["AnalogIn.o", "BusIn.o", "BusOut.o"]
    assert "mbed_wait_api_no_rtos.o" in children
