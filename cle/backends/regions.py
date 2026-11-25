from __future__ import annotations

import bisect
from collections.abc import Iterator

from .region import Region


class Regions[R: Region]:
    """
    A container class acting as a list of regions (sections or segments). Additionally, it keeps an sorted list of
    all regions that are mapped into memory to allow fast lookups.

    Regions are usually disjoint, but nothing guarantees it: a relocatable object can place several sections at one
    address and a malformed file can say anything at all. The sorted list is therefore ordered by start address only,
    and the lookups carry a running maximum of the end addresses beside it -- ``_max_end[i]`` is the highest end
    address among the first ``i + 1`` regions. That is sorted whether or not the regions are, which is what makes a
    bisection over it mean something; where the regions are disjoint it is each region's own end address.
    """

    def __init__(self, lst: list[R] | None = None):
        self._list = lst if lst is not None else []
        self._sorted_list: list[R] = []
        self._max_end: list[int] = []

        if self._list:
            self._sorted_list = self._make_sorted(self._list)
            self._max_end = self._make_max_end(self._sorted_list)

    @property
    def raw_list(self) -> list[R]:
        """
        Get the internal list. Any change to it is not tracked, and therefore _sorted_list will not be updated.
        Therefore you probably does not want to modify the list.

        :return:  The internal list container.
        :rtype:   list
        """

        return self._list

    @property
    def max_addr(self) -> int | None:
        """
        Get the highest address of all regions.

        :return: The highest address of all regions, or None if there is no region available.
        :rtype:   int or None
        """

        if self._max_end:
            return self._max_end[-1] - 1
        return None

    def __getitem__(self, idx: int) -> R:
        return self._list[idx]

    def __setitem__(self, idx: int, item: R) -> None:
        self._list[idx] = item

        # update self._sorted_list
        self._sorted_list = self._make_sorted(self._list)
        self._max_end = self._make_max_end(self._sorted_list)

    def __iter__(self) -> Iterator[R]:
        return iter(self._list)

    def __len__(self) -> int:
        return len(self._list)

    def __repr__(self):
        return f"<Regions: {repr(self._list)}>"

    def _rebase(self, delta):
        """
        Does regions rebasing to other base address.
        Modifies state of each internal object, so the list reference doesn't need to be updated,
        the same is also valid for sorted list as operation preserves the ordering.

        :param delta: Delta offset between an old and a new image bases
        :type delta: int
        """
        for x in self._list:
            x._rebase(delta)
        self._max_end = [end + delta for end in self._max_end]

    def append(self, region: R):
        """
        Append a new Region instance into the list.

        :param region: The region to append.
        """
        self._list.append(region)

        if self._is_region_mapped(region):
            index = bisect.bisect_left(self._sorted_list, region.vaddr, key=lambda x: x.vaddr)
            self._sorted_list.insert(index, region)
            self._insert_max_end(index, region)

    def remove(self, region: R) -> None:
        """
        Remove an existing Region instance from the list.

        :param region: The region to remove.
        """
        if self._is_region_mapped(region):
            index = self._sorted_list.index(region)
            self._sorted_list.pop(index)
            self._max_end.pop(index)
            self._refresh_max_end(index)
        self._list.remove(region)

    def find_region_containing(self, addr: int) -> R | None:
        """
        Find the region that contains a specific address. Returns None if none of the regions covers the address.

        :param addr:    The address.
        :return:        The region that covers the specific address, or None if no such region is found.
        """

        # Everything before this ends at or before addr, and everything from here on that starts after
        # addr is too late. The first of the few in between that covers addr is the answer.
        index = bisect.bisect_right(self._max_end, addr)
        while index < len(self._sorted_list):
            region = self._sorted_list[index]
            if region.vaddr > addr:
                break
            if region.contains_addr(addr):
                return region
            index += 1
        return None

    def find_region_next_to(self, addr: int) -> R | None:
        """
        Find the next region after the given address.

        :param addr: The address to test.
        :return:         The next region that goes after the given address, or None if there is no section after the
                         address,
        """

        # _max_end is sorted, so this is the first region whose end address is past addr
        pos = bisect.bisect_right(self._max_end, addr)
        if pos >= len(self._sorted_list):
            return None

        return self._sorted_list[pos]

    @staticmethod
    def _is_region_mapped(region: R) -> bool:
        # delayed import
        # pylint: disable=import-outside-toplevel
        from .elf.regions import ELFSection

        if region.memsize == 0:
            return False
        if isinstance(region, ELFSection):
            if not region.occupies_memory:
                return False
            if region.type == ELFSection.SHT_NOBITS and region.flags & ELFSection.SHF_TLS:
                # .tbss is the zero-filled tail of the thread-local template. Its address is where a
                # thread's own copy starts; in the image the linker puts the section that follows over
                # the top of it, so it holds none of the bytes at the addresses it claims.
                return False
        return True

    @staticmethod
    def _make_sorted(lst: list[R]) -> list[R]:
        """
        Return a sorted list of regions that are mapped into memory.

        :param lst:       A list of regions.
        :return:          A sorted list of regions.
        :rtype:           list
        """

        return sorted([r for r in lst if Regions._is_region_mapped(r)], key=lambda x: x.vaddr)

    @staticmethod
    def _make_max_end(sorted_list: list[R]) -> list[int]:
        """
        Return the running maximum of the regions' end addresses.
        """

        out = []
        running = 0
        for region in sorted_list:
            running = max(running, region.vaddr + region.memsize)
            out.append(running)
        return out

    def _insert_max_end(self, index: int, region: R) -> None:
        end = region.vaddr + region.memsize
        value = max(self._max_end[index - 1], end) if index else end
        self._max_end.insert(index, value)
        for i in range(index + 1, len(self._max_end)):
            if self._max_end[i] >= value:
                break
            self._max_end[i] = value

    def _refresh_max_end(self, index: int) -> None:
        running = self._max_end[index - 1] if index else 0
        for i in range(index, len(self._sorted_list)):
            region = self._sorted_list[i]
            running = max(running, region.vaddr + region.memsize)
            self._max_end[i] = running
