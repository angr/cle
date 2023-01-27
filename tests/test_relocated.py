import os

import cle


def test_relocated():
    filename = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "../../binaries/tests/i386/fauxware",
    )
    shared = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "../../binaries/tests/i386/prelinked",
    )
    ld = cle.Loader(filename, ld_path=[shared], rebase_granularity=0x1000000)
    assert ld.main_object.mapped_base == 0x8048000
    assert [x.mapped_base for x in ld.all_elf_objects] == [
        0x8048000,
        0x9000000,
        0xA000000,
    ]


def test_first_fit():
    filename = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests/x86_64/cfg_0")

    ld = cle.Loader(filename)
    assert ld.main_object.mapped_base < ld.shared_objects["libc.so.6"].mapped_base
    assert ld.shared_objects["libc.so.6"].mapped_base < ld.shared_objects["ld-linux-x86-64.so.2"].mapped_base

    # [<ELF Object cfg_0, maps [0x400000:0x601047]>,
    # <ELF Object libc.so.6, maps [0x1000000:0x13c42bf]>,
    # <ELF Object ld-linux-x86-64.so.2, maps [0x2000000:0x22241c7]>,
    # <ELFTLSObj Object ##cle_tls##, maps [0x3000000:0x3030000]>]

    ld = cle.Loader(filename, lib_opts={"libc.so.6": {"base_addr": 0x1234000}})
    assert ld.main_object.mapped_base < ld.shared_objects["ld-linux-x86-64.so.2"].mapped_base
    assert ld.shared_objects["ld-linux-x86-64.so.2"].mapped_base < ld.shared_objects["libc.so.6"].mapped_base

    # [<ELF Object cfg_0, maps [0x400000:0x601047]>,
    # <ELF Object ld-linux-x86-64.so.2, maps [0x1000000:0x12241c7]>,
    # <ELF Object libc.so.6, maps [0x1234000:0x15f82bf]>,
    # <ELFTLSObj Object ##cle_tls##, maps [0x2000000:0x2030000]>]

    ld = cle.Loader(
        filename,
        lib_opts={
            "libc.so.6": {"base_addr": 0x1234000},
            "ld-linux-x86-64.so.2": {"base_addr": 0},
        },
    )
    assert ld.shared_objects["ld-linux-x86-64.so.2"].mapped_base < ld.main_object.mapped_base
    assert ld.main_object.mapped_base < ld.shared_objects["libc.so.6"].mapped_base

    # [<ELF Object ld-linux-x86-64.so.2, maps [0x0:0x2241c7]>,
    # <ELF Object cfg_0, maps [0x400000:0x601047]>,
    # <ELFTLSObj Object ##cle_tls##, maps [0x1000000:0x1030000]>,
    # <ELF Object libc.so.6, maps [0x1234000:0x15f82bf]>]


def test_local_symbol_reloc():
    filename = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "../../binaries/tests/armel/btrfs.ko",
    )
    ld = cle.Loader(filename)

    # readelf -r btrfs.ko
    # Relocation section '.rel.init.text' at offset 0xfe318 contains 94 entries
    # Offset     Info    Type            Sym.Value  Sym. Name
    # 000000b4  00003c2b R_ARM_MOVW_ABS_NC 00000000   .LANCHOR0
    # 000000b8  00003c2c R_ARM_MOVT_ABS    00000000   .LANCHOR0
    # there are multiple symbols with name .LANCHOR0, those relocations shall
    # point to the first byte of .data section

    init_text_vaddr = ld.main_object.sections_map[".init.text"].vaddr
    data_vaddr = ld.main_object.sections_map[".data"].vaddr

    reloc_abs_nc = None
    reloc_abs = None
    for r in ld.main_object.relocs:
        if r.rebased_addr == init_text_vaddr + 0xB4:
            reloc_abs_nc = r
        if r.rebased_addr == init_text_vaddr + 0xB8:
            reloc_abs = r

    assert reloc_abs_nc is not None
    assert data_vaddr == reloc_abs_nc.resolvedby.rebased_addr
    assert reloc_abs is not None
    assert data_vaddr == reloc_abs.resolvedby.rebased_addr


if __name__ == "__main__":
    test_relocated()
    test_first_fit()
    test_local_symbol_reloc()
