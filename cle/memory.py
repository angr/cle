from __future__ import annotations

import bisect
import copy
import heapq
import itertools
import struct
import uuid
import weakref
from collections.abc import Iterator, Sized
from contextlib import contextmanager
from mmap import mmap
from typing import Any, cast

import archinfo

__all__ = ("ClemoryBase", "Clemory", "ClemoryView", "ClemoryTranslator", "UninitializedClemory")

_UNMAPPED = object()


def _contents_equal(left, right) -> bool:
    try:
        return bool(left == right)
    except Exception:  # pylint: disable=broad-exception-caught
        # Arbitrary list-backed memory values may have unusual equality implementations.
        return False


class _SemanticChangeEvent:
    """One byte/layout mutation propagated through a Clemory ownership graph."""

    __slots__ = ("_seen", "semantic", "structural")

    def __init__(self, structural: bool = False, semantic: bool = True):
        self._seen = weakref.WeakSet()
        self.semantic = semantic
        self.structural = structural

    def visit(self, memory: Clemory) -> bool:
        if memory in self._seen:
            return False
        self._seen.add(memory)
        return True


class ClemoryBase:
    """
    The base class of all Clemory classes.
    """

    __slots__ = (
        "_arch",
        "_pointer",
        "_public_backer_snapshot_token",
        "_public_backer_snapshots",
        "__weakref__",
    )

    def __init__(self, arch):
        self._arch = arch
        self._pointer = 0
        self._public_backer_snapshot_token = None
        self._public_backer_snapshots = {}

    def _reset_public_backer_snapshot_cache(self) -> None:
        self._public_backer_snapshot_token = None
        self._public_backer_snapshots = {}

    def _snapshot_public_backer(self, start, backer):
        if isinstance(backer, list):
            return list(backer)
        if isinstance(backer, bytes):
            return backer

        token = (self.semantic_token, self.layout_token)
        if self._public_backer_snapshot_token != token:
            self._public_backer_snapshot_token = token
            self._public_backer_snapshots.clear()

        source = backer.obj if isinstance(backer, memoryview) else backer
        key = start, id(source), len(backer)
        cached = self._public_backer_snapshots.get(key)
        if cached is None or cached[0] is not source:
            cached = source, bytes(backer)
            self._public_backer_snapshots[key] = cached
        return cached[1]

    def __getitem__(self, k):
        raise NotImplementedError

    def __setitem__(self, k, v):
        raise NotImplementedError

    def __contains__(self, k):
        raise NotImplementedError

    def load(self, addr, n):
        raise NotImplementedError

    def store(self, addr, data):
        raise NotImplementedError

    @property
    def semantic_token(self) -> str:
        """A stable identity for the current byte-level semantics of this memory."""
        raise NotImplementedError

    @property
    def layout_token(self) -> str:
        """A stable identity for the current backing layout of this memory."""
        raise NotImplementedError

    def _backers_for_reading(self, addr=0):
        """Yield private backing storage to trusted, read-only implementation code.

        Callers must never retain or mutate the returned objects. Public consumers must
        use :meth:`backers`, which returns detached snapshots.
        """
        raise NotImplementedError

    def _assert_read_access(self, addr: int, size: int) -> None:
        """Validate a read before any bytes are returned. Subclasses may impose access policies."""

    def backers(self, addr=0):
        """Iterate over detached snapshots of the mapped backers at or after ``addr``."""
        for start, backer in self._backers_for_reading(addr):
            yield start, self._snapshot_public_backer(start, backer)

    def find(self, data, search_min=None, search_max=None) -> Iterator[int]:
        raise NotImplementedError

    def unpack(self, addr: int, fmt: str) -> tuple[Any, ...]:
        """
        Use the ``struct`` module to unpack the data at address `addr` with the format `fmt`.
        """

        self._assert_read_access(addr, struct.calcsize(fmt))
        try:
            start, backer = next(self._backers_for_reading(addr))
        except StopIteration:
            raise KeyError(addr)  # pylint: disable=raise-missing-from

        if start > addr:
            raise KeyError(addr)

        try:
            return struct.unpack_from(fmt, backer, addr - start)
        except struct.error as e:
            if len(backer) - (addr - start) >= struct.calcsize(fmt):
                raise e
            raise KeyError(addr)  # pylint: disable=raise-missing-from

    def unpack_word(
        self, addr: int, size: int | None = None, signed: bool = False, endness: archinfo.Endness | None = None
    ) -> int:
        """
        Use the ``struct`` module to unpack a single integer from the address `addr`.

        You may override any of the attributes of the word being extracted:

        :param int size:    The size in bytes to pack/unpack. Defaults to wordsize (e.g. 4 bytes on
                            a 32 bit architecture)
        :param bool signed: Whether the data should be extracted signed/unsigned. Default unsigned
        :param archinfo.Endness endness: The endian to use in packing/unpacking. Defaults to memory endness
        """
        if size is not None and size > 8:
            # support larger wordsizes via recursive algorithm
            subsize = size >> 1
            if size != subsize << 1:
                raise ValueError("Cannot unpack non-power-of-two sizes")

            if endness is None:
                endness = self._arch.memory_endness
            if endness == archinfo.Endness.BE:
                lo_off, hi_off = subsize, 0
            elif endness == archinfo.Endness.LE:
                lo_off, hi_off = 0, subsize
            else:
                raise ValueError(f"Unsupported endness value {endness}.")

            lo = self.unpack_word(addr + lo_off, size=subsize, signed=False, endness=endness)
            hi = self.unpack_word(addr + hi_off, size=subsize, signed=signed, endness=endness)
            return (hi << (subsize << 3)) | lo

        return self.unpack(addr, self._arch.struct_fmt(size=size, signed=signed, endness=endness))[0]

    def load_null_terminated_bytes(self, addr: int, max_size: int = 4096) -> bytes:
        """
        Load a null-terminated string from memory at address `addr` with a maximum size of `max_size`.
        Useful
        """
        data = bytearray()
        for i in range(max_size):
            try:
                byte = self[addr + i]
            except KeyError:
                break
            if byte == 0:
                break
            data.append(byte)
        return bytes(data)

    def pack(self, addr: int, fmt: str, *data):
        """
        Use the ``struct`` module to pack `data` into memory at address `addr` with the format `fmt`.
        """

        try:
            start, backer = next(self._backers_for_reading(addr))
        except StopIteration:
            raise KeyError(addr)  # pylint: disable=raise-missing-from

        if start > addr:
            raise KeyError(addr)  # pylint: disable=raise-missing-from

        offset = addr - start
        size = struct.calcsize(fmt)
        if len(backer) - offset < size:
            raise KeyError(addr)
        if isinstance(backer, list):
            packed = bytearray(backer)
            struct.pack_into(fmt, packed, offset, *data)
            self.store(addr, packed[offset : offset + size])
            return None
        self.store(addr, struct.pack(fmt, *data))
        return None

    def pack_word(
        self,
        addr: int,
        data: int,
        size: int | None = None,
        signed: bool = False,
        endness: archinfo.Endness | None = None,
    ):
        """
        Use the ``struct`` module to pack a single integer `data` into memory at the address `addr`.

        You may override any of the attributes of the word being packed:

        :param int size:    The size in bytes to pack/unpack. Defaults to wordsize (e.g. 4 bytes on
                            a 32 bit architecture)
        :param bool signed: Whether the data should be extracted signed/unsigned. Default unsigned
        :param archinfo.Endness endness: The endian to use in packing/unpacking. Defaults to memory endness
        """
        if not signed:
            data &= (1 << (size * 8 if size is not None else self._arch.bits)) - 1
        return self.pack(addr, self._arch.struct_fmt(size=size, signed=signed, endness=endness), data)

    def read(self, nbytes: int):
        """
        The stream-like function that reads up to a number of bytes starting from the current
        position and updates the current position. Use with :func:`seek`.

        Up to `nbytes` bytes will be read, halting at the beginning of the first unmapped region
        encountered.
        """

        try:
            out = self.load(self._pointer, nbytes)
        except KeyError:
            return b""
        else:
            self._pointer += len(out)
            return out

    def seek(self, value: int):
        """
        The stream-like function that sets the "file's" current position. Use with :func:`read()`.

        :param value:        The position to seek to.
        """
        self._pointer = value

    def tell(self) -> int:
        return self._pointer

    def close(self):  # pylint: disable=no-self-use
        pass


class Clemory(ClemoryBase):
    """
    An object representing a memory space.

    Accesses can be made with [index] notation.
    """

    __slots__ = (
        "_backers",
        "_root",
        "consecutive",
        "min_addr",
        "max_addr",
        "_semantic_epoch",
        "_semantic_revision",
        "_layout_epoch",
        "_layout_revision",
        "_semantic_observers",
        "_semantic_suppression_depth",
    )

    def __init__(self, arch: archinfo.Arch, root: bool = False):
        super().__init__(arch)
        self._backers: list[tuple[int, bytearray | Clemory | list[int] | mmap]] = []
        self._root = root
        self.consecutive: bool = True
        self.min_addr: int = 0
        self.max_addr: int = 0
        self._semantic_epoch = uuid.uuid4().hex
        self._semantic_revision = 0
        self._layout_epoch = uuid.uuid4().hex
        self._layout_revision = 0
        self._semantic_observers: dict[int, weakref.WeakMethod] = {}
        self._semantic_suppression_depth = 0

    @property
    def semantic_token(self) -> str:
        return f"{self._semantic_epoch}:{self._semantic_revision}"

    @property
    def layout_token(self) -> str:
        return f"{self._layout_epoch}:{self._layout_revision}"

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        if self.__class__ is not Clemory:
            raise TypeError(f"Independent copies of {self.__class__.__name__} are not supported")
        existing = memo.get(id(self))
        if existing is not None:
            return existing

        clone = self.__class__.__new__(self.__class__)
        memo[id(self)] = clone

        cloned_backers = []
        for start, backer in self._backers:
            if isinstance(backer, mmap | memoryview):
                raise TypeError("Independent copies of mmap-backed Clemory objects are not supported")
            cloned_backer = copy.deepcopy(backer, memo)
            cloned_backers.append((start, cloned_backer))

        state = self.__getstate__()
        state["_arch"] = self._arch
        state["_backers"] = cloned_backers
        state["semantic_epoch"] = uuid.uuid4().hex
        state["semantic_revision"] = 0
        state["layout_epoch"] = uuid.uuid4().hex
        state["layout_revision"] = 0
        clone.__setstate__(state)
        return clone

    def _semantic_change(
        self, event=None, *, structural: bool = False, semantic: bool = True, force_forward: bool = False
    ) -> None:
        if self._semantic_suppression_depth:
            return
        if event is None:
            event = _SemanticChangeEvent(structural=structural, semantic=semantic)
        else:
            if structural:
                event.structural = True
            if semantic:
                event.semantic = True
        first_visit = event.visit(self)
        if not first_visit and not force_forward:
            return
        if first_visit:
            if event.semantic or event.structural:
                self._reset_public_backer_snapshot_cache()
            if event.semantic:
                self._semantic_revision += 1
            if event.structural:
                self._layout_revision += 1

        stale_observers = []
        for owner_id, observer_ref in self._semantic_observers.items():
            observer = observer_ref()
            if observer is None:
                stale_observers.append(owner_id)
            else:
                observer(event)
        for owner_id in stale_observers:
            self._semantic_observers.pop(owner_id, None)

    @contextmanager
    def _suppress_semantic_changes(self):
        self._semantic_suppression_depth += 1
        try:
            yield
        finally:
            self._semantic_suppression_depth -= 1

    def _nested_semantic_change(self, event) -> None:
        metadata_before = self.min_addr, self.max_addr, self.consecutive
        if event.structural:
            self._update_min_max()
        metadata_changed = metadata_before != (self.min_addr, self.max_addr, self.consecutive)
        self._semantic_change(event, semantic=False, force_forward=metadata_changed)

    def _contains_nested_clemory(self, candidate: Clemory) -> bool:
        if self is candidate:
            return True
        return any(
            isinstance(backer, Clemory) and backer._contains_nested_clemory(candidate) for _, backer in self._backers
        )

    @staticmethod
    def _backer_end(start, backer) -> int:
        return start + (backer.max_addr if isinstance(backer, Clemory) else len(cast(Sized, backer)))

    @staticmethod
    def _slice_backer(backer, start: int, end: int):
        sliced = backer[start:end]
        return bytearray(sliced) if isinstance(backer, mmap) else sliced

    def _prepare_overwrite_backers(self, start: int, data) -> tuple[list[tuple[int, Any]], tuple[Clemory, ...]]:
        end = start + len(cast(Sized, data))
        replacement_backers = []
        removed_children = []

        for backer_start, backer in self._backers:
            backer_end = self._backer_end(backer_start, backer)
            if backer_end <= start or end <= backer_start:
                replacement_backers.append((backer_start, backer))
                continue

            if isinstance(backer, Clemory):
                if start <= backer_start and backer_end <= end:
                    removed_children.append(backer)
                    continue
                raise ValueError("Cannot partially overwrite a backer which is itself a Clemory")

            if backer_start < start:
                replacement_backers.append((backer_start, self._slice_backer(backer, 0, start - backer_start)))
            if end < backer_end:
                replacement_backers.append((end, self._slice_backer(backer, end - backer_start, len(backer))))

        replacement_backers.append((start, data))
        replacement_backers.sort(key=lambda item: item[0])
        return replacement_backers, tuple(removed_children)

    def _observe_nested_clemory(self, child: Clemory) -> None:
        child._semantic_observers[id(self)] = weakref.WeakMethod(self._nested_semantic_change)

    def _stop_observing_nested_clemory(self, child: Clemory) -> None:
        if not any(backer is child for _, backer in self._backers):
            child._semantic_observers.pop(id(self), None)

    def _snapshot_range(self, start: int, size: int) -> tuple:
        """Snapshot the visible contents and mapped shape of a range without per-address lookups."""
        if size <= 0:
            return ()

        end = start + size
        segments = []
        for priority, (backer_start, backer, _) in enumerate(self._iter_all_backers_with_owners()):
            backer_end = backer_start + len(backer)
            visible_start = max(start, backer_start)
            visible_end = min(end, backer_end)
            if visible_start < visible_end:
                segments.append((visible_start, visible_end, priority, backer_start, backer))

        if not segments:
            return ()

        additions = {}
        removals = {}
        positions = {start, end}
        for index, (visible_start, visible_end, _, _, _) in enumerate(segments):
            additions.setdefault(visible_start, []).append(index)
            removals.setdefault(visible_end, []).append(index)
            positions.add(visible_start)
            positions.add(visible_end)

        active = set()
        active_priorities = []
        pieces = []
        sorted_positions = sorted(positions)
        for position, next_position in itertools.pairwise(sorted_positions):
            active.difference_update(removals.get(position, ()))
            for index in additions.get(position, ()):
                active.add(index)
                heapq.heappush(active_priorities, (segments[index][2], index))
            while active_priorities and active_priorities[0][1] not in active:
                heapq.heappop(active_priorities)
            if not active_priorities or position == next_position:
                continue

            _, index = active_priorities[0]
            _, _, _, backer_start, backer = segments[index]
            offset = position - backer_start
            length = next_position - position
            if isinstance(backer, list):
                pieces.append((position - start, "list", tuple(backer[offset : offset + length])))
            else:
                pieces.append((position - start, "bytes", bytes(memoryview(backer)[offset : offset + length])))

        groups = []
        for relative_start, kind, payload in pieces:
            if groups and groups[-1][1] == kind and groups[-1][3] == relative_start:
                groups[-1][2].append(payload)
                groups[-1] = groups[-1][:3] + (relative_start + len(payload),)
            else:
                groups.append((relative_start, kind, [payload], relative_start + len(payload)))

        snapshot = []
        for relative_start, kind, payloads, _ in groups:
            payload = tuple(itertools.chain.from_iterable(payloads)) if kind == "list" else b"".join(payloads)
            snapshot.append((relative_start, kind, payload))
        return tuple(snapshot)

    def add_backer(
        self, start: int, data: bytes | bytearray | memoryview | list[int] | Clemory | mmap, overwrite: bool = False
    ):
        """
        Adds a backer to the memory.

        :param start:   The address where the backer should be loaded.
        :param data:    The backer itself. Can be either a bytestring or another :class:`Clemory`.
        :param overwrite:
                        If True and the range overlaps any existing backer, the existing backer will be split up and
                        the overlapping part will be replaced with the new backer.
        """
        if not data:
            raise ValueError("Backer is empty!")

        if not isinstance(data, bytes | bytearray | memoryview | list | Clemory | mmap):
            raise TypeError("Data must be a bytes, list, or Clemory object.")
        if isinstance(data, Clemory) and data._root:
            raise ValueError("Cannot add a root clemory as a backer!")
        if isinstance(data, Clemory) and data._contains_nested_clemory(self):
            raise ValueError("Cannot create a cycle of nested Clemory backers")
        if overwrite and isinstance(data, Clemory):
            raise TypeError("Cannot perform an overwrite-add with a Clemory")
        if isinstance(data, list):
            data = list(data)
        elif not isinstance(data, Clemory):
            data = bytearray(data)

        data_size = len(cast(Sized, data)) if overwrite else 0
        before = self._snapshot_range(start, data_size) if overwrite else None
        layout_before = tuple((backer_start, id(backer)) for backer_start, backer in self._backers)
        inserted = False
        try:
            with self._suppress_semantic_changes():
                if overwrite:
                    replacement_backers, removed_children = self._prepare_overwrite_backers(start, data)
                    self._backers = replacement_backers
                    for removed_child in removed_children:
                        self._stop_observing_nested_clemory(removed_child)
                    self._update_min_max()
                    inserted = True
                else:
                    try:
                        existing, _ = next(self._backers_for_reading(start))
                    except StopIteration:
                        pass
                    else:
                        if existing <= start:
                            raise ValueError(f"Address {start:#x} is already backed!")
                    bisect.insort(self._backers, (start, data), key=lambda x: x[0])
                    inserted = True
                    if isinstance(data, Clemory):
                        self._observe_nested_clemory(data)
                    self._update_min_max()
        finally:
            if overwrite:
                after = self._snapshot_range(start, data_size)
                layout_changed = layout_before != tuple(
                    (backer_start, id(backer)) for backer_start, backer in self._backers
                )
                if layout_changed:
                    self._semantic_change(
                        structural=True,
                        semantic=not _contents_equal(before, after),
                    )
            elif inserted:
                self._semantic_change(structural=True)

    def split_backer(self, addr: int):
        """
        Ensures that ``addr`` is the start of a backer, if it is backed.
        """
        for start_addr, backer in self._backers:
            end_addr = start_addr + (backer.max_addr if isinstance(backer, Clemory) else len(backer))
            if not start_addr < addr < end_addr:
                continue
            if isinstance(backer, ClemoryBase):
                raise ValueError("Cannot split a backer which is itself a clemory")
            break
        else:
            return

        track_semantics = self._semantic_suppression_depth == 0
        before = self._snapshot_range(start_addr, len(backer)) if track_semantics else None
        rewired = False
        try:
            with self._suppress_semantic_changes():
                self.remove_backer(start_addr)
                rewired = True
                b0, b1 = backer[: addr - start_addr], backer[addr - start_addr :]
                self.add_backer(start_addr, b0)
                self.add_backer(addr, b1)
        finally:
            if track_semantics and rewired:
                after = self._snapshot_range(start_addr, len(backer))
                self._semantic_change(structural=True, semantic=not _contents_equal(before, after))

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{hex(self.min_addr)}:{hex(self.max_addr)}]>"

    def remove_backer(self, start):
        backer_idx = bisect.bisect_left(self._backers, start, key=lambda x: x[0])

        if len(self._backers) <= backer_idx or self._backers[backer_idx][0] != start:
            raise ValueError("Can't find backer to remove")

        removed = self._backers.pop(backer_idx)[1]
        try:
            self._update_min_max()
        finally:
            if isinstance(removed, Clemory):
                self._stop_observing_nested_clemory(removed)
            self._semantic_change(structural=True)

    def __iter__(self):
        for start, string in self._backers:
            if isinstance(string, bytes | list):
                for x in range(len(string)):
                    yield start + x
            else:
                for x in string:
                    yield start + x

    def __getitem__(self, k):
        for start, data in self._backers:
            if isinstance(data, bytearray | list):
                if 0 <= k - start < len(data):
                    return data[k - start]
            elif isinstance(data, Clemory):
                if data.min_addr <= k - start < data.max_addr:
                    try:
                        return data[k - start]
                    except KeyError:
                        pass
        raise KeyError(k)

    def __setitem__(self, k, v):
        for start, data in self._backers:
            if isinstance(data, bytearray | list):
                if 0 <= k - start < len(data):
                    offset = k - start
                    before = data[offset]
                    try:
                        data[offset] = v
                        return
                    finally:
                        try:
                            after = data[offset]
                        except Exception:  # pylint: disable=broad-exception-caught
                            after = _UNMAPPED
                        if not _contents_equal(before, after):
                            self._semantic_change()
            elif isinstance(data, Clemory):
                if data.min_addr <= k - start < data.max_addr:
                    try:
                        data[k - start] = v
                        return
                    except KeyError:
                        pass
        raise KeyError(k)

    def __contains__(self, k):
        # Fast path
        if self.consecutive:
            return self.min_addr <= k < self.max_addr
        else:
            # Check if this is an empty Clemory instance
            if not self._backers:
                return False
            # Check if it is out of the memory range
            if k < self.min_addr or k >= self.max_addr:
                return False

        try:
            self.__getitem__(k)
        except KeyError:
            return False
        else:
            return True

    def __getstate__(self):
        s = {
            "_arch": self._arch,
            "_backers": self._backers,
            "_pointer": self._pointer,
            "_root": self._root,
            "consecutive": self.consecutive,
            "min_addr": self.min_addr,
            "max_addr": self.max_addr,
            "semantic_epoch": self._semantic_epoch,
            "semantic_revision": self._semantic_revision,
            "layout_epoch": self._layout_epoch,
            "layout_revision": self._layout_revision,
        }

        return s

    def __setstate__(self, s):
        self._arch = s["_arch"]
        self._backers = s["_backers"]
        self._pointer = s["_pointer"]
        self._reset_public_backer_snapshot_cache()
        self._root = s["_root"]
        self.consecutive = s["consecutive"]
        self.min_addr = s["min_addr"]
        self.max_addr = s["max_addr"]
        self._semantic_epoch = uuid.uuid4().hex
        self._semantic_revision = s.get("semantic_revision", 0)
        self._layout_epoch = uuid.uuid4().hex
        self._layout_revision = s.get("layout_revision", 0)
        self._semantic_observers = {}
        self._semantic_suppression_depth = 0
        for _, backer in self._backers:
            if isinstance(backer, Clemory):
                self._observe_nested_clemory(backer)

    def _iter_all_backers_with_owners(
        self,
    ) -> Iterator[tuple[int, bytearray | memoryview | mmap | list[int], Clemory]]:
        for start, backer in self._backers:
            if isinstance(backer, Clemory):
                for child_start, child_backer, owner in backer._iter_all_backers_with_owners():
                    yield child_start + start, child_backer, owner
            else:
                yield start, backer, self

    def _assert_read_access(self, addr: int, size: int) -> None:
        for start, backer in self._backers:
            if isinstance(backer, Clemory):
                backer._assert_read_access(addr - start, size)

    def _iter_all_backers_with_owners_for_reading(
        self,
        addr: int,
    ) -> Iterator[tuple[int, bytes | bytearray | memoryview | mmap | list[int], Clemory]]:
        for start, backer in self._backers:
            if isinstance(backer, Clemory):
                for child_start, child_backer, owner in backer._backers_with_owners_for_reading(addr - start):
                    yield child_start + start, child_backer, owner
            else:
                yield start, backer, self

    def _iter_all_backers_with_owners_for_writing(
        self, addr: int, size: int
    ) -> Iterator[tuple[int, bytearray | memoryview | mmap | list[int], Clemory]]:
        for start, backer in self._backers:
            if isinstance(backer, Clemory):
                for child_start, child_backer, owner in backer._backers_with_owners_for_writing(addr - start, size):
                    yield child_start + start, child_backer, owner
            else:
                yield start, backer, self

    def _backers_with_owners(self, addr=0) -> Iterator[tuple[int, bytearray | memoryview | mmap | list[int], Clemory]]:
        for start, backer, owner in self._iter_all_backers_with_owners():
            if start + len(backer) > addr:
                yield start, backer, owner

    def _backers_with_owners_for_reading(
        self, addr=0
    ) -> Iterator[tuple[int, bytes | bytearray | memoryview | mmap | list[int], Clemory]]:
        for start, backer, owner in self._iter_all_backers_with_owners_for_reading(addr):
            if start + len(backer) > addr:
                yield start, backer, owner

    def _backers_with_owners_for_writing(
        self, addr: int, size: int
    ) -> Iterator[tuple[int, bytearray | memoryview | mmap | list[int], Clemory]]:
        for start, backer, owner in self._iter_all_backers_with_owners_for_writing(addr, size):
            if start + len(backer) > addr:
                yield start, backer, owner

    def _backers_for_reading(self, addr=0) -> Iterator[tuple[int, bytes | bytearray | memoryview | mmap | list[int]]]:
        """
        Iterate through each private backer for this clemory and all its children.

        :param addr:    An optional starting address - all backers before and not including this
                        address will be skipped.
        """

        for start, backer, _ in self._backers_with_owners_for_reading(addr):
            yield start, backer

    def load(self, addr, n):
        """
        Read up to `n` bytes at address `addr` in memory and return a bytes object.

        Reading will stop at the beginning of the first unallocated region found, or when
        `n` bytes have been read.
        """
        self._assert_read_access(addr, n)
        if n == 0:
            for start, backer, _ in self._backers_with_owners(addr):
                if start > addr:
                    break
                if start <= addr < start + len(backer):
                    if isinstance(backer, list):
                        raise TypeError("Can't load bytes from Clemory backed by list[int]")
                    return b""
            raise KeyError(addr)
        views = []

        for start, backer in self._backers_for_reading(addr):
            if start > addr:
                break
            if isinstance(backer, list):
                raise TypeError("Can't load bytes from Clemory backed by list[int]")
            offset = addr - start
            if not views and offset + n < len(backer):
                return bytes(memoryview(backer)[offset : offset + n])
            size = len(backer) - offset
            views.append(memoryview(backer)[offset : offset + n])

            addr += size
            n -= size

            if n <= 0:
                break

        if not views:
            raise KeyError(addr)
        return b"".join(views)

    def store(self, addr, data):
        """
        Write bytes from `data` at address `addr`.

        Note: If the store runs off the end of a backer and into unbacked space, this function
        will update the backer but also raise ``KeyError``.
        """
        changed_owners = set()
        try:
            # Materialize the policy-aware traversal before changing bytes. A nested memory can reject the write based
            # on its own access policy, and that rejection must happen before an earlier sibling backer is modified.
            backers = tuple(self._backers_with_owners_for_writing(addr, len(data)))
            for start, backer, owner in backers:
                if start > addr:
                    raise KeyError(addr)
                offset = addr - start
                size = len(backer) - offset
                write_size = min(len(data), size)
                before = tuple(backer[offset : offset + write_size])
                try:
                    backer[offset : offset + len(data)] = data if len(data) <= size else data[:size]
                finally:
                    try:
                        after = tuple(backer[offset : offset + write_size])
                    except Exception:  # pylint: disable=broad-exception-caught
                        changed_owners.add(owner)
                    else:
                        if not _contents_equal(before, after):
                            changed_owners.add(owner)

                addr += size
                data = data[size:]

                if not data:
                    break

            if data:
                raise KeyError(addr)
        finally:
            if changed_owners:
                event = _SemanticChangeEvent()
                for owner in changed_owners:
                    owner._semantic_change(event)

    def find(self, data, search_min=None, search_max=None) -> Iterator[int]:
        """
        Find all occurances of a bytestring in memory.

        :param bytes data:          The bytestring to search for
        :param int search_min:      Optional: The first address to include as valid
        :param int search_max:      Optional: The last address to include as valid
        :return Iterator[int]:      Iterates over addresses at which the bytestring occurs
        """
        if search_min is None:
            search_min = self.min_addr
        if search_max is None:
            search_max = self.max_addr

        for start, backer in self._backers:
            if isinstance(backer, Clemory):
                if search_max < backer.min_addr + start or search_min > backer.max_addr + start:
                    continue
                yield from (addr + start for addr in backer.find(data, search_min - start, search_max - start))
            elif isinstance(backer, list):
                raise TypeError("find is not supported for list-backed clemories")
            else:
                if search_max < start or search_min > start + len(data):
                    continue
                ptr = search_min - start - 1
                while True:
                    ptr += 1
                    ptr = backer.find(data, max(0, ptr))
                    if ptr == -1 or ptr + len(data) > search_max - start - 1:
                        break
                    yield ptr + start

    def _update_min_max(self):
        """
        Update the three properties of Clemory: consecutive, min_addr, and max_addr.
        """

        if not self._backers:
            self.consecutive = True
            self.min_addr = 0
            self.max_addr = 0
            return

        is_consecutive = True
        next_start = None
        min_addr, max_addr = None, None

        for start, backer in self._backers:
            if min_addr is None:
                min_addr = start

            if next_start is not None:
                # Check the predicted start equals to the real one
                if next_start != start:
                    is_consecutive = False

            if isinstance(backer, bytearray | list | mmap):
                backer_length = len(backer)
                # Update max_addr
                if max_addr is None or start + backer_length > max_addr:
                    max_addr = start + backer_length
                # Update the predicted starting address
                next_start = start + backer_length

            elif isinstance(backer, Clemory):
                if backer.max_addr is not None and backer.min_addr is not None:
                    # Update max_addr
                    if max_addr is None or start + backer.max_addr > max_addr:
                        max_addr = start + backer.max_addr
                    if backer.min_addr > 0:
                        is_consecutive = False
                    # Update the predicted starting address
                    next_start = start + backer.max_addr

                if not backer.consecutive:
                    is_consecutive = False
            else:
                raise TypeError(f"Unsupported backer type {type(backer)}.")

        assert min_addr is not None
        assert max_addr is not None
        self.consecutive = is_consecutive
        self.min_addr = min_addr
        self.max_addr = max_addr


class ClemoryView(ClemoryBase):
    """
    A Clemory which presents a subset of another Clemory as an address space.
    """

    def __init__(self, backer, start, end, offset=0):
        """
        :param backer:  The parent clemory to use
        :param start:   The address in the parent to start at
        :param end:     The address in the parent to end at (exclusive)
        :param offset:  Where the address space should start in this Clemory. Default 0.
        """
        super().__init__(backer._arch)
        self._backer = backer
        self._start = start
        self._end = end
        self._offset = offset
        self._endoffset = offset + (end - start)
        self._rebase = self._start - self._offset

    @property
    def semantic_token(self) -> str:
        return self._backer.semantic_token

    @property
    def layout_token(self) -> str:
        return self._backer.layout_token

    def __getitem__(self, k):
        if not self._offset <= k < self._endoffset:
            raise KeyError(k)
        return self._backer[k + self._rebase]

    def __setitem__(self, k, v):
        if not self._offset <= k < self._endoffset:
            raise KeyError(k)
        self._backer[k + self._rebase] = v

    def __contains__(self, k):
        if not self._offset <= k < self._endoffset:
            raise KeyError(k)
        return k + self._rebase in self._backer

    def _backers_for_reading(self, addr=0):
        for oaddr, backer in self._backer._backers_for_reading(addr=addr + self._rebase):
            taddr = oaddr - self._rebase
            if self._offset <= taddr < self._endoffset and self._offset <= taddr + len(backer) - 1 < self._endoffset:
                yield taddr, backer
            elif taddr >= self._endoffset or taddr + len(backer) - 1 < self._offset:
                continue
            else:
                # clamp it via a memoryview
                view = memoryview(backer)
                if taddr + len(backer) - 1 >= self._endoffset:
                    clamp_end = len(backer) - self._endoffset + taddr
                else:
                    clamp_end = len(backer)

                if taddr < self._offset:
                    clamp_start = self._offset - taddr
                else:
                    clamp_start = 0

                yield taddr, view[clamp_start:clamp_end]

    def load(self, addr, n):
        if n == 0:
            return b""
        if not self._offset <= addr < self._endoffset:
            raise KeyError(addr)
        if not self._offset <= addr + n - 1 < self._endoffset:
            raise KeyError(addr + n - 1)
        return self._backer.load(addr + self._rebase, n)

    def store(self, addr, data):
        if not data:
            return
        if not self._offset <= addr < self._endoffset:
            raise KeyError(addr)
        if not self._offset <= addr + len(data) - 1 < self._endoffset:
            raise KeyError(addr + len(data) - 1)
        self._backer.store(addr + self._rebase, data)

    def find(self, data, search_min=None, search_max=None) -> Iterator[int]:
        if search_min is None or search_min < self._start:
            search_min = self._start
        if search_max is None or search_max > self._end:
            search_max = self._end
        return self._backer.find(data, search_min=search_min + self._rebase, search_max=search_max + self._rebase)


class ClemoryTranslator(ClemoryBase):
    """
    Uses a function to translate between address spaces when accessing a child clemory. Intended to be used only as
    a stream object.
    """

    def __init__(self, backer: ClemoryBase, func):
        super().__init__(backer._arch)
        self.backer = backer
        self.func = func

    @property
    def semantic_token(self) -> str:
        return self.backer.semantic_token

    @property
    def layout_token(self) -> str:
        return self.backer.layout_token

    def __getitem__(self, k):
        return self.backer[self.func(k)]

    def __setitem__(self, k, v):
        self.backer[self.func(k)] = v

    def __contains__(self, k):
        return self.func(k) in self.backer

    def load(self, addr, n):
        return self.backer.load(self.func(addr), n)

    def store(self, addr, data):
        self.backer.store(self.func(addr), data)

    def pack(self, addr: int, fmt: str, *data):
        return self.backer.pack(self.func(addr), fmt, *data)

    def _backers_for_reading(self, addr=0):
        raise TypeError("Cannot access backers through address translation")

    def find(self, data, search_min=None, search_max=None) -> Iterator[int]:
        raise TypeError("Cannot perform finds through address translation")


class UninitializedClemory(Clemory):
    """
    A special kind of Clemory that acts as a placeholder for uninitialized and invalid memory.
    This is needed for the PAGEZERO segment for MachO binaries, which is 4GB worth of memory
    This does _not_ handle data being written to it, this is only for uninitialized memory that is technically occupied
    but should never be accessed
    """

    def __init__(self, arch, size):
        super().__init__(arch, root=False)
        self.max_addr = size

    def add_backer(self, start, data, overwrite=False):
        raise ValueError("Cannot add backers to an uninitialized clemory")

    def split_backer(self, addr):
        raise ValueError("This is an uninitialized clemory, it cannot be split")

    def remove_backer(self, start):
        raise ValueError("This is an uninitialized clemory, backers cannot be removed")

    def _backers_for_reading(self, addr=0):
        """
        Technically this object has no real backer
        We could create a fake backer on demand, but that would be a waste of memory, and code like the
        function prolog discovery for MachO binaries would search 4GB worth of nullbytes for a prolog,
        which is a waste of time
        Instead we just return an empty byte array, which seems to pass the test cases
        :param addr:
        :return:
        """
        yield (0, bytearray())

    def load(self, addr, n):
        return b"\x00" * n

    def store(self, addr, data):
        raise ValueError()

    def find(self, data, search_min=None, search_max=None) -> Iterator[int]:
        """
        The memory has no value, so matter what is searched for, it won't be found.
        """
        return iter(cast(tuple[int], ()))


class ClemoryReadOnlyView(ClemoryBase):
    """
    Represents an outermost read-only view of a Clemory object that does not allow updates. This class offers quick
    accesses to memory reads.
    """

    def __init__(self, arch, clemory: Clemory):
        super().__init__(arch)
        self._clemory = clemory
        self._flattened_backers: list[tuple[int, bytearray | memoryview]] = []

        # cache
        self._last_backer_pos: int | None = None
        self._layout_token = clemory.layout_token

        self._flatten_backers()

    @property
    def semantic_token(self) -> str:
        return self._clemory.semantic_token

    @property
    def layout_token(self) -> str:
        return self._clemory.layout_token

    def _refresh_if_stale(self) -> None:
        if getattr(self, "_layout_token", None) != self._clemory.layout_token:
            self._flattened_backers.clear()
            self._last_backer_pos = None
            self._flatten_backers()
            self._layout_token = self._clemory.layout_token

    def __getitem__(self, k) -> int:
        self._assert_read_access(k, 1)
        self._refresh_if_stale()
        # check cache first
        if self._last_backer_pos is not None:
            start, data = self._flattened_backers[self._last_backer_pos]
            if 0 <= k - start < len(data):
                return data[k - start]

        idx = bisect.bisect_right(self._flattened_backers, k, key=lambda x: x[0])
        if idx > 0:
            idx -= 1
        if idx >= len(self._flattened_backers):
            raise KeyError(k)
        start, data = self._flattened_backers[idx]
        if 0 <= k - start < len(data):
            self._last_backer_pos = idx
            return data[k - start]
        raise KeyError(k)

    def __setitem__(self, k, v):
        raise NotImplementedError("ClemoryReadOnlyView does not support item assignment")

    def load(self, addr: int, n: int) -> bytes:
        """
        Read up to `n` bytes at address `addr` in memory and return a bytes object.

        Reading will stop at the beginning of the first unallocated region found, or when
        `n` bytes have been read.
        """
        self._assert_read_access(addr, n)
        if n == 0:
            return self._clemory.load(addr, 0)
        self._refresh_if_stale()
        # check cache first
        if self._last_backer_pos is not None:
            start, data = self._flattened_backers[self._last_backer_pos]
            if 0 <= addr - start < len(data):
                offset = addr - start
                if offset + n < len(data):
                    return bytes(memoryview(data)[offset : offset + n])

        start_pos = bisect.bisect_right(self._flattened_backers, addr, key=lambda x: x[0])
        if start_pos > 0:
            start_pos -= 1
        views = []
        for i in range(start_pos, len(self._flattened_backers)):
            start, data = self._flattened_backers[i]
            if start > addr:
                break
            offset = addr - start
            if not 0 <= offset < len(data):
                break
            if not views and offset + n < len(data):
                # only cache if we do not need to read across backers
                self._last_backer_pos = i
                return bytes(memoryview(data)[offset : offset + n])
            size = len(data) - offset
            views.append(memoryview(data)[offset : offset + n])

            addr += size
            n -= size

            if n <= 0:
                break

        if not views:
            raise KeyError(addr)
        return b"".join(views)

    def store(self, addr, data):
        raise NotImplementedError("ClemoryReadOnlyView does not support storing")

    def _backers_for_reading(self, addr: int = 0):
        self._refresh_if_stale()
        start_pos = bisect.bisect_right(self._flattened_backers, addr, key=lambda x: x[0])
        if start_pos > 0:
            start_pos -= 1
        for idx in range(start_pos, len(self._flattened_backers)):
            start, data = self._flattened_backers[idx]
            if start > addr:
                break
            if 0 <= addr - start < len(data):
                yield start, data

    def unpack(self, addr, fmt):
        self._assert_read_access(addr, struct.calcsize(fmt))
        self._refresh_if_stale()
        if self._last_backer_pos is not None:
            start, data = self._flattened_backers[self._last_backer_pos]
            if 0 <= addr - start < len(data):
                try:
                    return struct.unpack_from(fmt, data, addr - start)
                except struct.error as ex:
                    if len(data) - (addr - start) >= struct.calcsize(fmt):
                        raise ex
                    raise KeyError(addr) from ex

        idx = bisect.bisect_right(self._flattened_backers, addr, key=lambda x: x[0])
        if idx > 0:
            idx -= 1
        if idx >= len(self._flattened_backers):
            raise KeyError(addr)
        start, data = self._flattened_backers[idx]
        if start > addr:
            raise KeyError(addr)
        try:
            v = struct.unpack_from(fmt, data, addr - start)
            self._last_backer_pos = idx
            return v
        except struct.error as ex:
            if len(data) - (addr - start) >= struct.calcsize(fmt):
                raise ex
            raise KeyError(addr) from ex

    def _assert_read_access(self, addr: int, size: int) -> None:
        self._clemory._assert_read_access(addr, size)

    def _flatten_backers(self):
        for start, backer in self._clemory._backers_for_reading():
            if isinstance(backer, bytearray | memoryview):
                self._flattened_backers.append((start, backer))
            elif isinstance(backer, list):
                raise TypeError("ClemoryReadOnlyView does not support list-backed clemories")
            elif isinstance(backer, Clemory):
                pass
            else:
                raise TypeError(f"Unsupported backer type {type(backer)}.")
