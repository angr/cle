# These tests intentionally exercise dynamically typed backers, invalid mutation attempts, and arch-less memories.
# pyright: reportArgumentType=false, reportAttributeAccessIssue=false, reportIndexIssue=false, reportOptionalOperand=false
from __future__ import annotations

import copy
import pickle
import struct
import sys
import timeit
import unittest
from mmap import mmap

import archinfo
import cffi

import cle
from cle.backends.macho.encrypted_sentinel_backer import CryptSentinel, EncryptedDataAccessException


@unittest.skipIf(sys.platform == "emscripten", "runtime CFFI compilation is unavailable in Pyodide")
def test_cclemory():  # pylint: disable=no-member
    # This is a test case for C-backed Clemory.

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"\x90" * 1000)
    clemory.add_backer(2000, b"A" * 1000)
    clemory.add_backer(3000, b"ABCDEFGH")

    ffi = cffi.FFI()
    ffi.cdef("""
        int memcmp(const void* s1, const void* s2, size_t n);
    """)
    c = ffi.verify("""
        #include <string.h>
    """)
    bytes_c = [ffi.from_buffer(backer) for _, backer in clemory.backers()]
    assert len(bytes_c) == 3
    out = c.memcmp(ffi.new("unsigned char []", b"\x90" * 10), bytes_c[0], 10)
    assert out == 0

    out = c.memcmp(ffi.new("unsigned char []", b"B" * 1000), bytes_c[1], 1000)
    assert out != 0
    out = c.memcmp(ffi.new("unsigned char []", b"A" * 1000), bytes_c[1], 1000)
    assert out == 0

    out = c.memcmp(ffi.new("unsigned char []", b"ABCDEFGH"), bytes_c[2], 8)
    assert out == 0


def test_clemory():
    # directly write bytes to backers
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0, b"A" * 20)
    clemory.add_backer(20, b"A" * 20)
    clemory.add_backer(50, b"A" * 20)
    assert len(clemory._backers) == 3

    clemory.store(10, b"B" * 30)

    assert len(clemory._backers) == 3
    assert clemory.load(0, 40) == b"A" * 10 + b"B" * 30

    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(10, b"A" * 20)
    clemory.add_backer(50, b"A" * 20)
    assert len(clemory._backers) == 2
    try:
        clemory.store(0, b"")
    except (KeyError, EncryptedDataAccessException):
        assert True
    else:
        assert False
    assert len(clemory._backers) == 2
    try:
        clemory.load(0, 25)
    except (KeyError, EncryptedDataAccessException):
        assert True
    else:
        assert False
    clemory.seek(0)
    assert clemory.read(25) == b""
    assert clemory.load(10, 25) == b"A" * 20


def performance_clemory_contains():
    # With the consecutive optimization:
    #   5.72 sec
    # Without the consecutive optimization:
    #   13.11 sec
    t = timeit.timeit(
        "0x400002 in clemory",
        setup="import cle; clemory = cle.Clemory(None, root=True); clemory.add_backer(0x400000, 'A' * 200000)",
        number=20000000,
    )
    print(t)


def test_clemory_contains():
    clemory = cle.Clemory(None, root=True)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 0
    assert clemory.consecutive is True

    # Add one backer
    clemory.add_backer(0, b"A" * 10)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 10
    assert clemory.consecutive is True

    # Add another backer
    clemory.add_backer(10, b"B" * 20)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 30
    assert clemory.consecutive is True

    # Add one more
    clemory.add_backer(40, b"A" * 30)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 70
    assert clemory.consecutive is False

    # Add another one to make it consecutive
    clemory.add_backer(30, b"C" * 10)
    assert clemory.min_addr == 0
    assert clemory.max_addr == 70
    assert clemory.consecutive is True


def test_clemory_semantic_token_tracks_public_mutations():
    clemory = cle.Clemory(archinfo.ArchAMD64(), root=True)
    token = clemory.semantic_token
    clemory.add_backer(0, b"abcd")
    assert clemory.semantic_token != token

    token = clemory.semantic_token
    clemory.store(0, b"abcd")
    clemory[0] = ord("a")
    clemory.pack(1, "B", ord("b"))
    clemory.pack_word(2, ord("c"), size=1)
    clemory.add_backer(0, b"abcd", overwrite=True)
    assert clemory.semantic_token == token

    for mutate, expected in (
        (lambda: clemory.store(0, b"xbcd"), b"xbcd"),
        (lambda: clemory.__setitem__(1, ord("y")), b"xycd"),
        (lambda: clemory.pack(2, "B", ord("z")), b"xyzd"),
        (lambda: clemory.pack_word(3, ord("!"), size=1), b"xyz!"),
        (lambda: clemory.add_backer(0, b"1234", overwrite=True), b"1234"),
    ):
        token = clemory.semantic_token
        mutate()
        assert clemory.semantic_token != token
        assert clemory.load(0, 4) == expected

    token = clemory.semantic_token
    layout_token = clemory.layout_token
    clemory.split_backer(2)
    assert clemory.semantic_token == token
    assert clemory.layout_token != layout_token
    assert clemory.load(0, 4) == b"1234"

    token = clemory.semantic_token
    clemory.remove_backer(0)
    assert clemory.semantic_token != token
    assert clemory.load(2, 2) == b"34"


def test_clemory_mutable_backer_aliases_and_public_backers_are_detached():
    def assert_bytes_detached(source, mutate_source):
        clemory = cle.Clemory(None, root=True)
        clemory.add_backer(0, source)
        token = clemory.semantic_token
        mutate_source()
        assert clemory.semantic_token == token
        assert clemory.load(0, 4) == b"abcd"

        _, exposed = next(clemory.backers())
        assert isinstance(exposed, bytes)
        assert next(clemory.backers())[1] is exposed
        try:
            exposed[0] = ord("z")
        except TypeError:
            pass
        else:
            raise AssertionError("Public backers must not expose writable memory")
        assert clemory.semantic_token == token
        assert clemory.load(0, 4) == b"abcd"

    bytearray_source = bytearray(b"abcd")
    assert_bytes_detached(bytearray_source, lambda: bytearray_source.__setitem__(0, ord("x")))

    memoryview_source = bytearray(b"abcd")
    assert_bytes_detached(memoryview(memoryview_source), lambda: memoryview_source.__setitem__(0, ord("x")))

    with mmap(-1, 4) as mmap_source:
        mmap_source[:] = b"abcd"
        assert_bytes_detached(mmap_source, lambda: mmap_source.__setitem__(0, ord("x")))

    list_source = [1, 2, 3, 4]
    list_memory = cle.Clemory(None, root=True)
    list_memory.add_backer(0, list_source)
    token = list_memory.semantic_token
    list_source[0] = 9
    assert list_memory.semantic_token == token
    assert list_memory[0] == 1
    _, exposed_list = next(list_memory.backers())
    assert exposed_list == [1, 2, 3, 4]
    exposed_list[0] = 9
    assert next(list_memory.backers())[1] == [1, 2, 3, 4]
    assert next(list_memory.backers())[1] is not exposed_list
    assert list_memory.semantic_token == token
    assert list_memory[0] == 1

    child = cle.Clemory(None)
    child.add_backer(0, b"abcd")
    parent = cle.Clemory(None, root=True)
    parent.add_backer(0, child)
    for memory in (parent, cle.ClemoryView(parent, 0, 4), cle.ClemoryReadOnlyView(None, parent)):
        _, exposed = next(memory.backers())
        assert isinstance(exposed, bytes)
        assert exposed == b"abcd"


def test_public_backer_snapshot_cache_tracks_mutations_copies_and_pickle():
    child = cle.Clemory(None)
    child.add_backer(0, b"a" * 32)
    parent = cle.Clemory(None, root=True)
    parent.add_backer(0, child)

    first = next(parent.backers())[1]
    assert next(parent.backers())[1] is first
    child.store(0, b"b")
    changed = next(parent.backers())[1]
    assert changed == b"b" + b"a" * 31
    assert changed is not first

    parent.store(0, b"b")
    assert next(parent.backers())[1] is changed

    independent = copy.deepcopy(parent)
    restored = pickle.loads(pickle.dumps(parent, -1))
    for clone in (independent, restored):
        snapshot = next(clone.backers())[1]
        assert snapshot == changed
        assert snapshot is next(clone.backers())[1]
        clone.store(1, b"c")
        assert next(clone.backers())[1] == b"bc" + b"a" * 30
        assert next(parent.backers())[1] is changed


def test_crypt_sentinel_guards_public_and_trusted_backer_iterators():
    memory = CryptSentinel(None)
    memory.add_backer(0, b"abcd")
    memory.set_crypt_info(1, 1, 2)

    for iterator in (memory.backers, memory._backers_for_reading):
        before = [(start, bytes(backer)) for start, backer in iterator(0)]
        after = [(start, bytes(backer)) for start, backer in iterator(3)]
        assert before == [(0, b"a"), (3, b"d")]
        assert after == [(3, b"d")]
        assert all(end <= 1 or start >= 3 for start, backer in before for end in (start + len(backer),))

        for addr in (1, 2):
            try:
                next(iterator(addr))
            except EncryptedDataAccessException:
                pass
            else:
                raise AssertionError("Encrypted memory must not be exposed through a backer iterator")

    public_before = list(memory.backers(0))
    public_after = list(memory.backers(0))
    assert [backer for _, backer in public_before] == [b"a", b"d"]
    assert all(left is right for (_, left), (_, right) in zip(public_before, public_after))

    assert memory.load(0, 1) == b"a"
    assert memory.load(3, 1) == b"d"
    assert memory.load(1, 0) == b""
    memory.store(0, b"A")
    memory.store(3, b"D")
    token = memory.semantic_token
    memory.store(1, b"")
    assert memory.semantic_token == token

    for addr, size in ((0, 2), (1, 1), (2, 1), (2, 2)):
        try:
            memory.load(addr, size)
        except EncryptedDataAccessException:
            pass
        else:
            raise AssertionError("Loads overlapping encrypted memory must fail")

        try:
            memory.store(addr, b"x" * size)
        except EncryptedDataAccessException:
            pass
        else:
            raise AssertionError("Stores overlapping encrypted memory must fail")

    assert memory.load(0, 1) == b"A"
    assert memory.load(3, 1) == b"D"

    parent = cle.Clemory(None, root=True)
    parent.add_backer(0x1000, memory)
    for operation in (
        lambda: memory[1],
        lambda: memory.__setitem__(1, ord("X")),
        lambda: parent[0x1001],
        lambda: parent.__setitem__(0x1001, ord("X")),
        lambda: parent.store(0x1001, b"X"),
    ):
        try:
            operation()
        except EncryptedDataAccessException:
            pass
        else:
            raise AssertionError("Encrypted bytes must not be accessible through item or nested store APIs")

    memory.set_crypt_info(0, 1, 2)
    assert parent.load(0x1000, 4) == b"AbcD"


def test_nested_policy_aware_backers_preserve_negative_child_addresses():
    child = cle.Clemory(None)
    child.add_backer(-4, b"abcd")
    parent = cle.Clemory(None, root=True)
    parent.add_backer(0x1000, child)

    assert parent.load(0xFFC, 4) == b"abcd"
    assert list(parent.backers(0xFFC)) == [(0xFFC, b"abcd")]


def test_crypt_sentinel_metadata_changes_refresh_nested_owners_and_views():
    memory = CryptSentinel(archinfo.ArchAMD64())
    memory.add_backer(0, b"abcd")
    parent = cle.Clemory(archinfo.ArchAMD64(), root=True)
    parent.add_backer(0x1000, memory)
    read_only = cle.ClemoryReadOnlyView(parent._arch, parent)
    assert read_only.load(0x1000, 4) == b"abcd"

    memory_semantic_token = memory.semantic_token
    memory_layout_token = memory.layout_token
    parent_semantic_token = parent.semantic_token
    parent_layout_token = parent.layout_token
    memory.set_crypt_info(1, 1, 2)
    assert memory.semantic_token != memory_semantic_token
    assert memory.layout_token != memory_layout_token
    assert parent.semantic_token != parent_semantic_token
    assert parent.layout_token != parent_layout_token
    first_enabled_token = memory.semantic_token
    zero_length_tokens = tuple(owner.semantic_token for owner in (memory, parent, read_only))
    assert memory.load(1, 0) == parent.load(0x1001, 0) == read_only.load(0x1001, 0) == b""
    assert tuple(owner.semantic_token for owner in (memory, parent, read_only)) == zero_length_tokens
    assert read_only.load(0x1000, 1) == b"a"
    assert read_only.load(0x1003, 1) == b"d"
    for owner in (parent, read_only):
        try:
            owner.load(0x1000, 4)
        except EncryptedDataAccessException:
            pass
        else:
            raise AssertionError("A nested read crossing encrypted bytes must fail before returning a prefix")
    for owner in (parent, read_only):
        try:
            owner.load(0x1001, 1)
        except (KeyError, EncryptedDataAccessException):
            pass
        else:
            raise AssertionError("Nested encrypted bytes must not be exposed by an owner")

    # The crypt identifier itself is not semantic when the effective interval is unchanged.
    memory.set_crypt_info(2, 1, 2)
    assert memory.semantic_token == first_enabled_token

    parent_token = parent.semantic_token
    memory.set_crypt_info(1, 2, 2)
    assert parent.semantic_token != parent_token
    assert read_only.load(0x1001, 1) == b"b"
    try:
        read_only.load(0x1002, 1)
    except (KeyError, EncryptedDataAccessException):
        pass
    else:
        raise AssertionError("Moving the encrypted interval must refresh cached owner views")

    parent_token = parent.semantic_token
    memory.set_crypt_info(0, 2, 2)
    assert parent.semantic_token != parent_token
    assert read_only.load(0x1000, 4) == b"abcd"

    memory.set_crypt_info(1, 1, 2)
    assert memory.semantic_token != first_enabled_token
    try:
        read_only.load(0x1001, 1)
    except (KeyError, EncryptedDataAccessException):
        pass
    else:
        raise AssertionError("Crypt interval ABA must not reuse stale view state")

    restored = pickle.loads(pickle.dumps(memory, -1))
    assert restored.semantic_token != memory.semantic_token
    assert restored.layout_token != memory.layout_token
    assert restored.load(0, 1) == b"a"
    try:
        restored.load(1, 1)
    except EncryptedDataAccessException:
        pass
    else:
        raise AssertionError("Pickling an active sentinel must preserve its encrypted interval")

    try:
        copy.deepcopy(memory)
    except TypeError:
        pass
    else:
        raise AssertionError("Independent CryptSentinel copies are intentionally unsupported")

    legacy_state = memory.__getstate__()
    legacy_state.pop("crypt_start")
    legacy_state.pop("crypt_end")
    legacy_state.pop("is_encrypted")
    legacy = CryptSentinel.__new__(CryptSentinel)
    legacy.__setstate__(legacy_state)
    assert legacy.load(0, 4) == b"abcd"


def test_clemory_partial_store_and_delegating_views_track_semantics():
    clemory = cle.Clemory(archinfo.ArchAMD64(), root=True)
    clemory.add_backer(0, b"ab")

    token = clemory.semantic_token
    try:
        clemory.store(0, b"xy!")
    except KeyError:
        pass
    else:
        raise AssertionError("A partial store into an unmapped range must fail")
    assert clemory.load(0, 2) == b"xy"
    assert clemory.semantic_token != token

    token = clemory.semantic_token
    try:
        clemory.store(0, b"xy!")
    except KeyError:
        pass
    else:
        raise AssertionError("A partial store into an unmapped range must fail")
    assert clemory.semantic_token == token

    view = cle.ClemoryView(clemory, 0, 2)
    translator = cle.ClemoryTranslator(clemory, lambda addr: addr)
    read_only = cle.ClemoryReadOnlyView(None, clemory)
    assert view.semantic_token == translator.semantic_token == read_only.semantic_token == clemory.semantic_token

    token = clemory.semantic_token
    view[0] = ord("v")
    assert clemory.semantic_token != token
    token = clemory.semantic_token
    translator.store(1, b"t")
    assert clemory.semantic_token != token
    token = clemory.semantic_token
    view.pack(0, "B", ord("p"))
    assert clemory.semantic_token != token
    token = clemory.semantic_token
    translator.pack(0, "B", ord("q"))
    assert clemory.semantic_token != token
    token = clemory.semantic_token
    translator.pack_word(1, ord("r"), size=1)
    assert clemory.semantic_token != token


def test_nested_clemory_mutations_propagate_once_to_all_owners():
    child = cle.Clemory(None)
    child.add_backer(0, b"ab")
    first = cle.Clemory(None, root=True)
    second = cle.Clemory(None, root=True)
    first.add_backer(0, child)
    first.add_backer(2, b"cd")
    second.add_backer(10, child)

    first_revision = first._semantic_revision
    second_revision = second._semantic_revision
    child_revision = child._semantic_revision
    first.store(0, b"wxyz")
    assert first.load(0, 4) == b"wxyz"
    assert second.load(10, 2) == b"wx"
    assert first._semantic_revision == first_revision + 1
    assert second._semantic_revision == second_revision + 1
    assert child._semantic_revision == child_revision + 1

    first_revision = first._semantic_revision
    second_revision = second._semantic_revision
    child_revision = child._semantic_revision
    first.pack(0, "H", struct.unpack("H", b"12")[0])
    assert first._semantic_revision == first_revision + 1
    assert second._semantic_revision == second_revision + 1
    assert child._semantic_revision == child_revision + 1

    first.remove_backer(0)
    first_revision = first._semantic_revision
    second_revision = second._semantic_revision
    child.store(0, b"zz")
    assert first._semantic_revision == first_revision
    assert second._semantic_revision == second_revision + 1


def test_nested_clemory_structural_changes_recompute_diamond_ancestors():
    leaf = cle.Clemory(None)
    leaf.add_backer(0, b"ab")
    left = cle.Clemory(None)
    right = cle.Clemory(None)
    left.add_backer(0, leaf)
    right.add_backer(3, leaf)
    root = cle.Clemory(None)
    root.add_backer(0, left)
    root.add_backer(10, right)
    grandroot = cle.Clemory(None, root=True)
    grandroot.add_backer(100, root)

    memories = leaf, left, right, root, grandroot
    revisions = tuple(memory._semantic_revision for memory in memories)
    layout_revisions = tuple(memory._layout_revision for memory in memories)
    leaf.add_backer(2, b"cd")

    assert tuple(memory._semantic_revision for memory in memories) == tuple(revision + 1 for revision in revisions)
    assert tuple(memory._layout_revision for memory in memories) == tuple(revision + 1 for revision in layout_revisions)
    assert (left.min_addr, left.max_addr, left.consecutive) == (0, 4, True)
    assert (right.min_addr, right.max_addr, right.consecutive) == (3, 7, True)
    assert (root.min_addr, root.max_addr, root.consecutive) == (0, 17, False)
    assert (grandroot.min_addr, grandroot.max_addr, grandroot.consecutive) == (100, 117, False)
    assert root.load(13, 4) == b"abcd"
    assert grandroot.load(113, 4) == b"abcd"
    assert 16 in root and 116 in grandroot

    revisions = tuple(memory._semantic_revision for memory in memories)
    layout_revisions = tuple(memory._layout_revision for memory in memories)
    leaf.add_backer(0, b"XY", overwrite=True)

    assert tuple(memory._semantic_revision for memory in memories) == tuple(revision + 1 for revision in revisions)
    assert tuple(memory._layout_revision for memory in memories) == tuple(revision + 1 for revision in layout_revisions)
    assert (root.min_addr, root.max_addr) == (0, 17)
    assert (grandroot.min_addr, grandroot.max_addr) == (100, 117)
    assert root.load(13, 4) == b"XYcd"
    assert grandroot.load(113, 4) == b"XYcd"

    revisions = tuple(memory._semantic_revision for memory in memories)
    layout_revisions = tuple(memory._layout_revision for memory in memories)
    leaf.remove_backer(2)

    assert tuple(memory._semantic_revision for memory in memories) == tuple(revision + 1 for revision in revisions)
    assert tuple(memory._layout_revision for memory in memories) == tuple(revision + 1 for revision in layout_revisions)
    assert (left.min_addr, left.max_addr, left.consecutive) == (0, 2, True)
    assert (right.min_addr, right.max_addr, right.consecutive) == (3, 5, True)
    assert (root.min_addr, root.max_addr, root.consecutive) == (0, 15, False)
    assert (grandroot.min_addr, grandroot.max_addr, grandroot.consecutive) == (100, 115, False)
    assert root.load(13, 2) == b"XY"
    assert grandroot.load(113, 2) == b"XY"
    assert 14 in root and 114 in grandroot
    assert 15 not in root and 115 not in grandroot


def test_nested_clemory_cycles_are_rejected_without_mutation():
    first = cle.Clemory(None)
    first.add_backer(0, b"a")
    second = cle.Clemory(None)
    second.add_backer(0, first)

    token = first.semantic_token
    backers = list(first._backers)
    try:
        first.add_backer(2, second)
    except ValueError:
        pass
    else:
        raise AssertionError("Nested Clemory ownership cycles must be rejected")

    assert first.semantic_token == token
    assert first._backers == backers
    assert first.load(0, 1) == b"a"


def test_nested_clemory_duplicate_child_observers_detach_only_after_last_backer():
    child = cle.Clemory(None)
    child.add_backer(0, b"ab")
    parent = cle.Clemory(None, root=True)
    parent.add_backer(0, child)
    parent.add_backer(10, child)
    restored = pickle.loads(pickle.dumps(parent, -1))

    for owner in (parent, restored):
        owned_child = owner._backers[0][1]
        assert owned_child is owner._backers[1][1]
        revision = owner._semantic_revision
        owned_child.store(0, b"xy")
        assert owner._semantic_revision == revision + 1

        owner.add_backer(0, b"QQ", overwrite=True)
        revision = owner._semantic_revision
        owned_child.store(0, b"12")
        assert owner._semantic_revision == revision + 1
        assert owner.load(10, 2) == b"12"

        owner.remove_backer(10)
        revision = owner._semantic_revision
        owned_child.store(0, b"zz")
        assert owner._semantic_revision == revision


def test_clemory_read_only_view_refreshes_after_layout_only_changes():
    child = cle.Clemory(None)
    child.add_backer(0, b"abcd")
    root = cle.Clemory(None, root=True)
    root.add_backer(0, child)
    read_only = cle.ClemoryReadOnlyView(None, root)

    semantic_token = root.semantic_token
    layout_token = root.layout_token
    root.add_backer(0, b"abcd", overwrite=True)
    assert root.semantic_token == semantic_token
    assert root.layout_token != layout_token
    child.store(0, b"xy")
    assert root.semantic_token == semantic_token
    assert root.load(0, 4) == read_only.load(0, 4) == b"abcd"

    raw_root = cle.Clemory(None, root=True)
    raw_root.add_backer(0, b"abcd")
    raw_read_only = cle.ClemoryReadOnlyView(None, raw_root)
    semantic_token = raw_root.semantic_token
    layout_token = raw_root.layout_token
    raw_root.split_backer(2)
    assert raw_root.semantic_token == semantic_token
    assert raw_root.layout_token != layout_token
    raw_root.store(0, b"12")
    assert raw_root.load(0, 4) == raw_read_only.load(0, 4) == b"12cd"

    del raw_read_only._layout_token
    legacy_read_only = pickle.loads(pickle.dumps(raw_read_only, -1))
    assert legacy_read_only.load(0, 4) == b"12cd"
    assert legacy_read_only.layout_token != raw_root.layout_token


def test_clemory_overwrite_snapshot_handles_overlap_priority_and_negative_addresses():
    overlapping = cle.Clemory(None, root=True)
    overlapping.add_backer(20, b"B" * 40)
    overlapping.add_backer(10, b"C" * 5)
    overlapping.add_backer(0, b"A" * 100)
    assert overlapping.load(50, 1) == b"A"

    token = overlapping.semantic_token
    overlapping.add_backer(50, b"Z", overwrite=True)
    assert overlapping.semantic_token != token
    assert overlapping.load(50, 1) == b"Z"
    assert len([backer for start, backer in overlapping._backers if start == 50]) == 1

    negative = cle.Clemory(None, root=True)
    negative.add_backer(-4, b"abcd")
    semantic_token = negative.semantic_token
    layout_token = negative.layout_token
    negative.add_backer(-4, b"abcd", overwrite=True)
    assert negative.semantic_token == semantic_token
    assert negative.layout_token != layout_token

    semantic_token = negative.semantic_token
    negative.add_backer(-4, b"wxyz", overwrite=True)
    assert negative.semantic_token != semantic_token
    assert negative.load(-4, 4) == b"wxyz"


def test_clemory_overwrite_preflights_partial_nested_backers_atomically():
    child = cle.Clemory(None)
    child.add_backer(0, b"abcd")
    parent = cle.Clemory(None, root=True)
    parent.add_backer(10, child)
    semantic_token = parent.semantic_token
    layout_token = parent.layout_token
    backers = list(parent._backers)

    try:
        parent.add_backer(11, b"X", overwrite=True)
    except ValueError:
        pass
    else:
        raise AssertionError("A partial nested-Clemory overwrite must be rejected")

    assert parent.semantic_token == semantic_token
    assert parent.layout_token == layout_token
    assert parent._backers == backers
    assert parent.load(10, 4) == b"abcd"
    child.store(0, b"wxyz")
    assert parent.semantic_token != semantic_token
    assert parent.load(10, 4) == b"wxyz"


def test_clemory_overwrite_snapshot_uses_bulk_backers_not_address_lookups():
    class NoAddressLookupsClemory(cle.Clemory):
        def __getitem__(self, _):
            raise AssertionError("Overwrite snapshots must not perform one lookup per address")

    clemory = NoAddressLookupsClemory(None, root=True)
    data = b"A" * (2 * 1024 * 1024)
    clemory.add_backer(0, data)
    semantic_token = clemory.semantic_token
    clemory.add_backer(0, data, overwrite=True)
    assert clemory.semantic_token == semantic_token
    assert clemory.load(0, len(data)) == data


def test_clemory_semantic_token_pickle_and_legacy_state():
    child = cle.Clemory(None)
    child.add_backer(0, b"ab")
    clemory = cle.Clemory(None, root=True)
    clemory.add_backer(0x1000, child)
    token = clemory.semantic_token
    layout_token = clemory.layout_token

    restored = pickle.loads(pickle.dumps(clemory, -1))
    assert restored.semantic_token != token
    assert restored.layout_token != layout_token
    assert restored.load(0x1000, 2) == b"ab"
    restored_child = restored._backers[0][1]
    restored_token = restored.semantic_token
    restored_child.store(0, b"xy")
    assert restored.semantic_token != restored_token
    assert clemory.load(0x1000, 2) == b"ab"

    child.store(0, b"12")
    assert clemory.semantic_token != restored.semantic_token
    assert clemory.load(0x1000, 2) == b"12"
    assert restored.load(0x1000, 2) == b"xy"

    legacy_state = clemory.__getstate__()
    legacy_state.pop("semantic_epoch")
    legacy_state.pop("semantic_revision")
    legacy_state.pop("layout_epoch")
    legacy_state.pop("layout_revision")
    legacy = cle.Clemory.__new__(cle.Clemory)
    legacy.__setstate__(legacy_state)
    legacy_token = legacy.semantic_token
    legacy.store(0x1000, b"34")
    assert legacy.semantic_token != legacy_token


def test_clemory_copy_contract_freshens_pickle_and_deepcopies_independently():
    child = cle.Clemory(None)
    child.add_backer(0, b"ab")
    source = cle.Clemory(None, root=True)
    source.add_backer(0, child)
    source.add_backer(10, child)

    assert copy.copy(source) is source

    cloned = copy.deepcopy(source)
    assert cloned.semantic_token != source.semantic_token
    assert cloned.layout_token != source.layout_token
    assert cloned._semantic_revision == 0
    assert cloned.load(0, 2) == cloned.load(10, 2) == b"ab"
    cloned_child = cloned._backers[0][1]
    assert cloned_child is cloned._backers[1][1]
    assert cloned_child is not child

    source_token = source.semantic_token
    cloned_token = cloned.semantic_token
    cloned_child.store(0, b"xy")
    assert cloned.semantic_token != cloned_token
    assert source.semantic_token == source_token
    assert cloned.load(0, 2) == cloned.load(10, 2) == b"xy"
    assert source.load(0, 2) == source.load(10, 2) == b"ab"


def main():
    g = globals()
    for func_name, func in g.items():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()


if __name__ == "__main__":
    main()
