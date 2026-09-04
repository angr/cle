#!/usr/bin/env python
from __future__ import annotations

import os
import struct
import unittest

import cle
from cle.backends.elf.relocation import riscv64 as riscv


def get_real_instr(r):
    try:
        if r.relative_addr % 2 != 0:
            return None
        probing = r.owner.memory.unpack_word(r.relative_addr, size=2)
        if (probing & 0x3) != 0x3:
            return probing
        return r.owner.memory.unpack_word(r.relative_addr, size=4)
    except (KeyError, struct.error):
        return None


def sign_extend(x, bits):
    m = 1 << (bits - 1)
    return (x ^ m) - m


def decode_u_imm20(insn32):
    return insn32 & 0xFFFFF000


def decode_i_imm12_raw(insn32):
    return (insn32 >> 20) & 0xFFF


def decode_s_imm12_raw(insn32: int) -> int:
    imm = ((insn32 >> 25) & 0x7F) << 5 | ((insn32 >> 7) & 0x1F)
    return imm & 0xFFF


def decode_b_off(insn32):
    imm = (
        ((insn32 >> 31) & 0x1) << 12
        | ((insn32 >> 7) & 0x1) << 11
        | ((insn32 >> 25) & 0x3F) << 5
        | ((insn32 >> 8) & 0xF) << 1
    )
    return sign_extend(imm, 13)


def decode_j_off(insn32):
    imm = (
        ((insn32 >> 31) & 0x1) << 20
        | ((insn32 >> 21) & 0x3FF) << 1
        | ((insn32 >> 20) & 0x1) << 11
        | ((insn32 >> 12) & 0xFF) << 12
    )
    return sign_extend(imm, 21)


def decode_cb_off(insn16):
    off = (
        ((insn16 >> 12) & 1) << 8  # off[8]
        | ((insn16 >> 6) & 1) << 7  # off[7]
        | ((insn16 >> 5) & 1) << 6  # off[6]
        | ((insn16 >> 2) & 1) << 5  # off[5]
        | ((insn16 >> 11) & 1) << 4  # off[4]
        | ((insn16 >> 10) & 1) << 3  # off[3]
        | ((insn16 >> 4) & 1) << 2  # off[2]
        | ((insn16 >> 3) & 1) << 1  # off[1]
    )
    return sign_extend(off, 9)


def decode_cj_off(insn16):
    off = (
        ((insn16 >> 12) & 1) << 11  # off[11]
        | ((insn16 >> 11) & 1) << 4  # off[4]
        | ((insn16 >> 9) & 0x3) << 8  # off[9:8]
        | ((insn16 >> 8) & 1) << 10  # off[10]
        | ((insn16 >> 7) & 1) << 6  # off[6]
        | ((insn16 >> 6) & 1) << 7  # off[7]
        | ((insn16 >> 3) & 0x7) << 1  # off[3:1]
        | ((insn16 >> 2) & 1) << 5  # off[5]
    )
    return sign_extend(off, 12)


def expect_abs(r):
    assert r.resolvedby is not None
    return r.resolvedby.rebased_addr + r.addend


def expect_pcrel(r, P: int | None = None):
    assert r.resolvedby is not None
    S = r.resolvedby.rebased_addr
    A = r.addend
    if P is None:
        P = r.rebased_addr
    return S + A - P


def find_paired_hi20(obj, label_addr: int):
    """
    For PCREL_LO12*, resolvedby usually points to a label at the HI20 site (AUIPC).
    We find a HI20/GOT_HI20 relocation whose rebased_addr == label_addr.
    """
    hi_types = []
    # TODO: We don't implement R_RISCV_TLS_GOT_HI20 now.
    for name in ("R_RISCV_PCREL_HI20", "R_RISCV_GOT_HI20", "R_RISCV_TLS_GOT_HI20"):
        if hasattr(riscv, name):
            hi_types.append(getattr(riscv, name))

    for rr in obj.relocs:
        if rr.rebased_addr == label_addr and any(isinstance(rr, t) for t in hi_types):
            return rr
    return None


def run_reloc_test_on_file(file_path, base_addr=0x210000):
    try:
        loader = cle.Loader(file_path, main_opts={"base_addr": base_addr})
    except Exception as e:
        raise AssertionError(f"Failed to load {file_path}: {e}") from e

    obj = loader.main_object
    relocations = obj.relocs

    instruction_reloc_types = (
        riscv.R_RISCV_PCREL_HI20,
        riscv.R_RISCV_PCREL_LO12_I,
        riscv.R_RISCV_PCREL_LO12_S,
        riscv.R_RISCV_HI20,
        riscv.R_RISCV_LO12_I,
        riscv.R_RISCV_LO12_S,
        riscv.R_RISCV_CALL,
        riscv.R_RISCV_CALL_PLT,
        riscv.R_RISCV_JAL,
        riscv.R_RISCV_BRANCH,
        riscv.R_RISCV_RVC_JUMP,
        riscv.R_RISCV_RVC_BRANCH,
    )

    validated = 0

    for r in relocations:
        if isinstance(r, riscv.R_RISCV_NONE):
            continue

        if not r.resolved:
            continue

        # Data relocations
        if isinstance(r, riscv.R_RISCV_64):
            assert r.resolvedby is not None
            data = r.owner.memory.unpack_word(r.relative_addr, size=8)
            expected = expect_abs(r)
            assert data == expected, (r, hex(data), hex(expected))
            validated += 1
            continue

        if isinstance(r, riscv.R_RISCV_32):
            assert r.resolvedby is not None
            data = r.owner.memory.unpack_word(r.relative_addr, size=4)
            expected = expect_abs(r) & 0xFFFFFFFF
            assert data == expected, (r, hex(data), hex(expected))
            validated += 1
            continue

        if not isinstance(r, instruction_reloc_types):
            continue

        instr = get_real_instr(r)
        if instr is None:
            raise AssertionError(f"Unable to read instruction for relocation: {r!r}")

        if isinstance(r, riscv.R_RISCV_PCREL_HI20):
            assert (instr & 0x7F) == 0b0010111
            off = expect_pcrel(r)
            hi_exp = (((off + 0x800) >> 12) & 0xFFFFF) << 12
            hi_enc = decode_u_imm20(instr)
            assert hi_enc == hi_exp, (r, hex(hi_enc), hex(hi_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_PCREL_LO12_I):
            assert instr & 0x7F in {0b0010011, 0b0000011, 0b0000111, 0b1100111}
            assert r.resolvedby is not None
            label_addr = r.resolvedby.rebased_addr
            hi = find_paired_hi20(obj, label_addr)
            assert hi is not None and hi.resolved, f"LO12_I without matching HI20 at {label_addr:#x}: {r!r}"
            off = expect_pcrel(hi)
            lo_exp = (off + r.addend) & 0xFFF
            lo_enc = decode_i_imm12_raw(instr)
            assert lo_enc == lo_exp, (r, hex(lo_enc), hex(lo_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_PCREL_LO12_S):
            assert (instr & 0x7F) == 0b0100011
            assert r.resolvedby is not None
            label_addr = r.resolvedby.rebased_addr
            hi = find_paired_hi20(obj, label_addr)
            assert hi is not None and hi.resolved, f"LO12_S without matching HI20 at {label_addr:#x}: {r!r}"

            off = expect_pcrel(hi)
            lo_exp = (off + r.addend) & 0xFFF
            lo_enc = decode_s_imm12_raw(instr)
            assert lo_enc == lo_exp, (r, hex(lo_enc), hex(lo_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_HI20):
            assert instr & 0x7F in {0b0010111, 0b0110111}
            val = expect_abs(r)
            hi_exp = (((val + 0x800) >> 12) & 0xFFFFF) << 12
            hi_enc = decode_u_imm20(instr)
            assert hi_enc == hi_exp, (r, hex(hi_enc), hex(hi_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_LO12_I):
            assert instr & 0x7F in {0b0010011, 0b0000011, 0b0000111, 0b1100111}
            val = expect_abs(r)
            lo_exp = val & 0xFFF
            lo_enc = decode_i_imm12_raw(instr)
            assert lo_enc == lo_exp, (r, hex(lo_enc), hex(lo_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_LO12_S):
            assert (instr & 0x7F) == 0b0100011
            val = expect_abs(r)
            lo_exp = val & 0xFFF
            lo_enc = decode_s_imm12_raw(instr)
            assert lo_enc == lo_exp, (r, hex(lo_enc), hex(lo_exp))
            validated += 1
        elif isinstance(r, (riscv.R_RISCV_CALL, riscv.R_RISCV_CALL_PLT)):
            assert (instr & 0x7F) == 0b0010111
            next_instr = r.owner.memory.unpack_word(r.relative_addr + 4, size=4)
            assert (next_instr & 0x7F) == 0b1100111

            off = expect_pcrel(r)
            hi_exp = (((off + 0x800) >> 12) & 0xFFFFF) << 12
            hi_enc = decode_u_imm20(instr)
            assert hi_enc == hi_exp, (r, hex(hi_enc), hex(hi_exp))

            lo_exp = off & 0xFFF
            lo_enc = decode_i_imm12_raw(next_instr)
            assert lo_enc == lo_exp, (r, hex(lo_enc), hex(lo_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_JAL):
            assert (instr & 0x7F) == 0b1101111
            off_enc = decode_j_off(instr)
            off_exp = expect_pcrel(r)
            assert off_enc == off_exp, (r, hex(off_enc), hex(off_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_BRANCH):
            assert (instr & 0x7F) == 0b1100011
            off_enc = decode_b_off(instr)
            off_exp = expect_pcrel(r)
            assert off_enc == off_exp, (r, hex(off_enc), hex(off_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_RVC_JUMP):
            assert (instr & 0x3) == 0b01
            assert (instr >> 13) & 0x7 in {0b101, 0b001}
            off_enc = decode_cj_off(instr)
            off_exp = expect_pcrel(r)
            assert off_enc == off_exp, (r, hex(off_enc), hex(off_exp))
            validated += 1
        elif isinstance(r, riscv.R_RISCV_RVC_BRANCH):
            assert (instr & 0x3) == 0b01
            assert (instr >> 13) & 0x7 in {0b110, 0b111}
            off_enc = decode_cb_off(instr)
            off_exp = expect_pcrel(r)
            assert off_enc == off_exp, (r, hex(off_enc), hex(off_exp))
            validated += 1

    assert validated > 0, f"No relocations validated for {file_path}"


def test_riscv64_all_relocations() -> None:
    riscv_test_dir = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "..",
        "binaries",
        "tests",
        "riscv64",
    )

    if not os.path.isdir(riscv_test_dir):
        raise unittest.SkipTest(f"Directory not found: {riscv_test_dir}")

    test_files = [os.path.join(riscv_test_dir, f) for f in os.listdir(riscv_test_dir) if f.endswith((".o", ".so"))]

    if not test_files:
        raise unittest.SkipTest(f"No .o or .so files found in {riscv_test_dir}")

    for file_path in sorted(test_files):
        run_reloc_test_on_file(file_path)


if __name__ == "__main__":
    test_riscv64_all_relocations()
