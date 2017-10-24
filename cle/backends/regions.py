
from ..utils import key_bisect_find, key_bisect_insort_left

#
# Container
#


class Regions(object):
    """
    A container class acting as a list of regions (sections or segments). Additionally, it keeps an sorted list of
    all regions that are mapped into memory to allow fast lookups.

    We assume none of the regions overlap with others.
    """

    def __init__(self, lst=None):
        self._list = lst if lst is not None else []

        if self._list:
            self._sorted_list = self._make_sorted(self._list)
        else:
            self._sorted_list = []

    @property
    def raw_list(self):
        """
        Get the internal list. Any change to it is not tracked, and therefore _sorted_list will not be updated.
        Therefore you probably does not want to modify the list.

        :return:  The internal list container.
        :rtype:   list
        """

        return self._list

    @property
    def max_addr(self):
        """
        Get the highest address of all regions.

        :return: The highest address of all regions, or None if there is no region available.
        rtype:   int or None
        """

        if self._sorted_list:
            return self._sorted_list[-1].max_addr
        return None

    def __getitem__(self, idx):
        return self._list[idx]

    def __setitem__(self, idx, item):
        self._list[idx] = item

        # update self._sorted_list
        self._sorted_list = self._make_sorted(self._list)

    def __len__(self):
        return len(self._list)

    def __repr__(self):
        return "<Regions: %s>" % repr(self._list)

    def _rebase(self, delta):
        """
        Does regions rebasing to other base address.
        Modifies state of each internal object, so the list reference doesn't need to be updated,
        the same is also valid for sorted list as operation preserves the ordering.

        :param delta: Delta offset between an old and a new image bases
        :type delta: int
        """
        map(lambda x: x._rebase(delta), self._list)

    def append(self, region):
        """
        Append a new Region instance into the list.

        :param Region region: The region to append.
        """
        self._list.append(region)

        if self._is_region_mapped(region):
            key_bisect_insort_left(self._sorted_list, region, keyfunc=lambda r: r.vaddr)

    def find_region_containing(self, addr):
        """
        Find the region that contains a specific address. Returns None if none of the regions covers the address.

        :param addr:    The address.
        :type addr:     int
        :return:        The region that covers the specific address, or None if no such region is found.
        :rtype:         Region or None
        """

        pos = key_bisect_find(self._sorted_list, addr,
                              keyfunc=lambda r: r if type(r) in (int, long) else r.vaddr + r.memsize)
        if pos >= len(self._sorted_list):
            return None
        region = self._sorted_list[pos]
        if region.contains_addr(addr):
            return region
        return None

    @staticmethod
    def _is_region_mapped(region):

        # delayed import
        from .elf.regions import ELFSection

        mapped = True
        if region.memsize == 0:
            mapped = False
        elif isinstance(region, ELFSection) and not region.occupies_memory:
            mapped = False
        return mapped

    @staticmethod
    def _make_sorted(lst):
        """
        Return a sorted list of regions that are mapped into memory.

        :param list lst:  A list of regions.
        :return:          A sorted list of regions.
        :rtype:           list
        """

        return sorted([ r for r in lst if Regions._is_region_mapped(r) ], key=lambda x: x.vaddr)
