from __future__ import annotations

from pathlib import Path

import cle

TEST_BASE = Path(__file__).resolve().parents[2] / "binaries" / "tests"


def test_backed_cgc_preserves_relative_executable_backer():
    binary = TEST_BASE / "i386" / "patchrex" / "indirect_jump_test_Ofast"
    loader = cle.Loader(
        binary,
        auto_load_libs=False,
        main_opts={
            "backend": "backedcgc",
            "memory_backer": {},
            "register_backer": {"eip": 0x8048FB4},
        },
    )

    obj = loader.main_object
    assert isinstance(obj, cle.BackedCGC)
    assert obj.entry == 0x8048FB4
    assert obj.thread_registers() == {"eip": 0x8048FB4}
    assert [start for start, _ in obj.memory._backers] == [0]
    assert loader.memory.load(0x8048000, 4) == b"\x7fCGC"
