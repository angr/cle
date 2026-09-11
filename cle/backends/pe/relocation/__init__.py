from __future__ import annotations

import logging

from .arm import relocation_table_arm
from .generic import relocation_table_generic
from .mips import relocation_table_mips
from .riscv import relocation_table_riscv

# Keyed on archinfo's arch.name, which is what PE._make_reloc looks these up with.
ALL_RELOCATIONS = {
    "AARCH64": relocation_table_generic,
    "AMD64": relocation_table_generic,
    "ARMCortexM": relocation_table_generic | relocation_table_arm,
    "ARMEL": relocation_table_generic | relocation_table_arm,
    "ARMHF": relocation_table_generic | relocation_table_arm,
    "MIPS32": relocation_table_generic | relocation_table_mips,
    "PPC32": relocation_table_generic,
    "RISCV64": relocation_table_generic | relocation_table_riscv,
    "X86": relocation_table_generic,
}

log = logging.getLogger(name=__name__)
complaint_log = set()


def get_relocation(arch, r_type):
    if r_type == 0:
        return None
    try:
        return ALL_RELOCATIONS[arch][r_type]
    except KeyError:
        if (arch, r_type) not in complaint_log:
            complaint_log.add((arch, r_type))
            log.warning("Unknown reloc %d on %s", r_type, arch)
        return None
