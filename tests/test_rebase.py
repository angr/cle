from __future__ import annotations

import os
import struct
import tempfile

import cle


class MockBackend(cle.backends.Backend):  # pylint: disable=missing-class-docstring
    def __init__(self, size, **kwargs):
        super().__init__("/dev/zero", None, **kwargs)
        self.size = size
        self.pic = True
        self.has_memory = False

    @property
    def max_addr(self):
        return self.mapped_base + self.size - 1


def sparse_elf32(loads):
    """
    Assemble an ET_EXEC i386 ELF with one PT_LOAD per ``(vaddr, data)`` pair and no section headers.
    """
    ehsize, phentsize = 52, 32
    offset = ehsize + phentsize * len(loads)

    phdrs = b""
    body = b""
    for vaddr, data in loads:
        # p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align
        phdrs += struct.pack("<IIIIIIII", 1, offset, vaddr, vaddr, len(data), len(data), 5, 0x1000)
        body += data
        offset += len(data)

    ehdr = struct.pack(
        "<16sHHIIIIIHHHHHH",
        b"\x7fELF\x01\x01\x01\x00" + bytes(8),
        2,  # ET_EXEC
        3,  # EM_386
        1,
        loads[0][0],  # e_entry
        ehsize,  # e_phoff
        0,  # e_shoff
        0,  # e_flags
        ehsize,
        phentsize,
        len(loads),
        0,
        0,
        0,
    )
    return ehdr + phdrs + body


def check_sparse_elf(loads):
    """
    Load a two-segment i386 image whose segments are 4 GB apart, then ask for the objects the loader
    places itself. Everything the loader maps must be readable through its memory.
    """
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "sparse")
        with open(path, "wb") as f:
            f.write(sparse_elf32(loads))

        ld = cle.Loader(path, auto_load_libs=False, main_opts={"backend": "elf"})
        assert (ld.main_object.min_addr, ld.main_object.max_addr) == (0xF800, 0xFFF00FFF)

        extern = ld.extern_object
        tls = ld.tls.new_thread()

        for obj in (extern, tls):
            # 0xf800 is where the main object starts: an object placed inside its span would be
            # unreachable, since the main object is a single backer of the loader's memory.
            assert obj.max_addr < 0xF800
            ld.memory.unpack_word(obj.min_addr)


def test_sparse_main_object():
    # The gap below the main object is 0xf800 bytes wide, smaller than the default rebase
    # granularity of 0x100000, and the space above it is smaller still.
    check_sparse_elf([(0xF800, bytes(0x7F5)), (0xFFF00000, bytes(0x1000))])


def test_sparse_main_object_unsorted_program_headers():
    # Program headers do not have to be sorted by vaddr, and cle keeps them in file order.
    check_sparse_elf([(0xFFF00000, bytes(0x1000)), (0xF800, bytes(0x7F5))])


def test_rebase_granularity_is_not_a_hard_object_limit():
    """
    Rounding every object up to the rebase granularity caps the loader at one object per granule.
    A static archive with thousands of tiny members hits that cap with the address space nearly
    empty; a granularity of 0x10000000 reaches the same state after sixteen objects.
    """
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../binaries/tests/i386/manysum")
    ld = cle.Loader(path, auto_load_libs=False, rebase_granularity=0x10000000)

    objects = []
    for _ in range(64):
        obj = MockBackend(0x1000, arch=ld.main_object.arch)
        ld.dynamic_load(obj)
        objects.append(obj)

    placed = sorted(objects, key=lambda o: o.min_addr)
    assert placed[-1].max_addr < 2**32
    for lower, upper in zip(placed, placed[1:]):
        assert lower.max_addr < upper.min_addr
    for obj in objects:
        assert ld.find_object_containing(obj.min_addr) is obj


if __name__ == "__main__":
    test_sparse_main_object()
    test_sparse_main_object_unsorted_program_headers()
    test_rebase_granularity_is_not_a_hard_object_limit()
