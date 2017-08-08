from ..utils import key_bisect_find, key_bisect_insort_left

class Region(object):
    """
    A region of memory that is mapped in the object's file.

    :ivar offset:       The offset into the file the region starts.
    :ivar vaddr:        The virtual address.
    :ivar filesize:     The size of the region in the file.
    :ivar memsize:      The size of the region when loaded into memory.

    The prefix `v-` on a variable or parameter name indicates that it refers to the virtual, loaded memory space,
    while a corresponding variable without the `v-` refers to the flat zero-based memory of the file.

    When used next to each other, `addr` and `offset` refer to virtual memory address and file offset, respectively.
    """
    def __init__(self, offset, vaddr, filesize, memsize):
        self.vaddr = vaddr
        self.memsize = memsize
        self.filesize = filesize
        self.offset = offset

    def _rebase(self, delta):
        """
        Does region rebasing to other base address.
        Intended for usage by loader's add_object to reflect the rebasing.

        :param delta: Delta offset between an old and a new image bases
        :type delta: int
        """
        self.vaddr += delta

    def contains_addr(self, addr):
        """
        Does this region contain this virtual address?
        """
        return self.vaddr <= addr < self.vaddr + self.memsize

    def contains_offset(self, offset):
        """
        Does this region contain this offset into the file?
        """
        return self.offset <= offset < self.offset + self.filesize

    def addr_to_offset(self, addr):
        """
        Convert a virtual memory address into a file offset
        """
        offset = addr - self.vaddr + self.offset
        if not self.contains_offset(offset):
            return None
        return offset

    def offset_to_addr(self, offset):
        """
        Convert a file offset into a virtual memory address
        """
        addr = offset - self.offset + self.vaddr
        if not self.contains_addr(addr):
            return None
        return addr

    def __repr__(self):
        return '{}({})'.format(self.__class__, ', '.join(['{}=0x{:x}'.format(k, v) for k, v in self.__dict__.iteritems()]))

    @property
    def max_addr(self):
        """
        The maximum virtual address of this region
        """
        return self.vaddr + self.memsize - 1

    @property
    def min_addr(self):
        """
        The minimum virtual address of this region
        """
        return self.vaddr

    @property
    def max_offset(self):
        """
        The maximum file offset of this region
        """
        return self.offset + self.filesize - 1

    def min_offset(self):
        """
        The minimum file offset of this region
        """
        return self.offset


class Segment(Region):
    pass


class Section(Region):
    """
    Simple representation of a loaded section.

    :ivar str name:     The name of the section
    """
    def __init__(self, name, offset, vaddr, size):
        """
        :param str name:    The name of the section
        :param int offset:  The offset into the binary file this section begins
        :param int vaddr:   The address in virtual memory this section begins
        :param int size:    How large this section is
        """
        super(Section, self).__init__(offset, vaddr, size, size)
        self.name = name

    @property
    def is_readable(self):
        """
        Whether this section has read permissions
        """
        raise NotImplementedError()

    @property
    def is_writable(self):
        """
        Whether this section has write permissions
        """
        raise NotImplementedError()

    @property
    def is_executable(self):
        """
        Whether this section has execute permissions
        """
        raise NotImplementedError()

    def __repr__(self):
        return "<%s | offset %#x, vaddr %#x, size %#x>" % (
            self.name if self.name else "Unnamed",
            self.offset,
            self.vaddr,
            self.memsize
        )

#
# Container
#


class Regions(object):
    """
    A container class acting as a list of regions (sections or segments). Additionally, it keeps an sorted list of
    those regions to allow fast lookups.

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
        :return: None
        """

        self._list.append(region)
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
    def _make_sorted(lst):
        """
        Return a sorted list of regions.

        :param list lst:  A list of regions.
        :return:          A sorted list of regions.
        :rtype:           list
        """

        return sorted(lst, key=lambda x: x.vaddr)
