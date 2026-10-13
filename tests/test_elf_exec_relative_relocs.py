from __future__ import annotations

import io
import struct

import cle

R_ARM_RELATIVE = 23
LINK_BASE = 0x60800000


def _static_pie_exec_arm() -> bytes:
    """
    A minimal ET_EXEC ARM image linked at a non-zero base that carries DT_REL R_ARM_RELATIVE entries, the shape
    U-Boot produces for static-PIE builds. The relocated words hold link-time addresses (REL addends in place).
    """
    ehsize, phentsize, phnum = 52, 32, 2
    # one PT_LOAD at file offset 0, so vaddr == LINK_BASE + file offset
    image = bytearray(ehsize + phentsize * phnum)
    image += b"\0" * (0x100 - len(image))
    image += struct.pack("<II", LINK_BASE + 0x100, LINK_BASE + 0x104)  # table @0x100: two link-time addresses
    off = {}
    rel = struct.pack("<II", LINK_BASE + 0x100, R_ARM_RELATIVE) + struct.pack("<II", LINK_BASE + 0x104, R_ARM_RELATIVE)
    for name, blob in (("rel", rel), ("dynsym", b"\0" * 16), ("dynstr", b"\0")):
        off[name] = len(image)
        image += blob
        image += b"\0" * (-len(image) % 4)
    off["dynamic"] = len(image)
    dynamic = [
        (5, LINK_BASE + off["dynstr"]),  # DT_STRTAB
        (6, LINK_BASE + off["dynsym"]),  # DT_SYMTAB
        (10, 1),  # DT_STRSZ
        (11, 16),  # DT_SYMENT
        (17, LINK_BASE + off["rel"]),  # DT_REL
        (18, len(rel)),  # DT_RELSZ
        (19, 8),  # DT_RELENT
        (0, 0),
    ]
    image += b"".join(struct.pack("<ii", t, v) for t, v in dynamic)
    dynsz = len(image) - off["dynamic"]

    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01" + b"\0" * 9,
        2,  # ET_EXEC
        40,  # EM_ARM
        1,
        LINK_BASE,
        ehsize,
        0,
        0x05000000,  # EF_ARM_EABI_VER5
        ehsize,
        phentsize,
        phnum,
        0,
        0,
        0,
    )
    load = struct.pack("<IIIIIIII", 1, 0, LINK_BASE, LINK_BASE, len(image), len(image), 7, 0x1000)
    dyn = struct.pack("<IIIIIIII", 2, off["dynamic"], LINK_BASE + off["dynamic"], 0, dynsz, dynsz, 6, 4)
    image[: ehsize + phentsize * phnum] = ehdr + load + dyn
    return bytes(image)


def test_exec_relative_reloc_keeps_link_time_address():
    ld = cle.Loader(io.BytesIO(_static_pie_exec_arm()), auto_load_libs=False)
    obj = ld.main_object
    assert obj.mapped_base == obj.linked_base == LINK_BASE
    assert {r.rebased_addr for r in obj.relocs} == {LINK_BASE + 0x100, LINK_BASE + 0x104}
    assert ld.memory.unpack_word(LINK_BASE + 0x100) == LINK_BASE + 0x100
    assert ld.memory.unpack_word(LINK_BASE + 0x104) == LINK_BASE + 0x104


def test_exec_relative_reloc_rebased_by_delta():
    new_base = 0x10000000
    ld = cle.Loader(
        io.BytesIO(_static_pie_exec_arm()),
        auto_load_libs=False,
        main_opts={"base_addr": new_base, "force_rebase": True},
    )
    delta = new_base - LINK_BASE
    assert ld.main_object.mapped_base == new_base
    assert ld.memory.unpack_word(new_base + 0x100) == LINK_BASE + 0x100 + delta
    assert ld.memory.unpack_word(new_base + 0x104) == LINK_BASE + 0x104 + delta
