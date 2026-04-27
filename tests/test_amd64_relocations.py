#!/usr/bin/env python
from __future__ import annotations

import os

import cle
from cle.backends.elf.relocation.amd64 import R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT


def test_amd64_jumpslot_globdat_ignore_addend():
    """R_X86_64_JUMP_SLOT and R_X86_64_GLOB_DAT calculation is S only.

    Per the AMD64 ABI (psABI), these relocations resolve to ``S``; the addend
    field is unused. glibc's static linker, however, emits non-zero addends on
    JUMP_SLOT entries pointing at the lazy PLT trampoline (the value the GOT
    slot holds before the runtime resolver patches it). CLE used to compute
    ``S + A``, which produced the pre-resolution stub address rather than the
    resolved symbol address. Anything that loaded a glibc-built ``libc.so.6``
    and then read the GOT (e.g. concrete-execution engines that skip the
    runtime linker) would jump to garbage.
    """
    test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"))
    libc = os.path.join(test_location, "x86_64", "libc.so.6")
    ld = cle.Loader(libc, auto_load_libs=False, main_opts={"base_addr": 0})

    js = next(r for r in ld.main_object.relocs if isinstance(r, R_X86_64_JUMP_SLOT) and r.resolvedby is not None)
    gd = next(r for r in ld.main_object.relocs if isinstance(r, R_X86_64_GLOB_DAT) and r.resolvedby is not None)

    for r in (js, gd):
        # Force a non-zero addend simulating a glibc-style lazy-stub offset.
        r.is_rela = True
        r._addend = 0x12345
        assert r.value == r.resolvedby.rebased_addr


if __name__ == "__main__":
    test_amd64_jumpslot_globdat_ignore_addend()
