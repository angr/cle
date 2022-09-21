from collections import OrderedDict

from . import Backend
from .region import EmptySegment
from .. import Clemory, Regions

class NonEmptySegment(EmptySegment):
    @property
    def only_contains_uninitialized_data(self):
        return False

class LazyClemory(Clemory):
    def __init__(self, owner: 'LazyBackend', chunk_size=2**12, max_resident=2**24):
        """
        chunk_size must be a power of two
        """
        self.owner = owner
        self.lru_order = OrderedDict()
        self.chunk_size = chunk_size
        self.max_resident = max_resident
        self.resident = 0

        super().__init__(self.owner.arch)

    @property
    def _real_max_resident(self):
        return self.max_resident + self.chunk_size * 2

    def __getitem__(self, k):
        return self.load(k, 1)[0]

    def __setitem__(self, k, v):
        return self.store(k, bytes(([v])))

    def __contains__(self, k):
        return self.region_containing(k)[0] is not None

    def region_containing(self, k):
        seg = self.owner.find_segment_containing(k)
        if seg is None:
            return None, None
        return seg.vaddr, seg.memsize

    def __iter__(self):
        raise TypeError("Cannot enumerate data of LazyClemory")

    def _split_to_unmapped(self, addr, end):
        """
        returns list of [(start addr, end addr)]
        """
        missing = []
        for start, backer in self.backers(addr):
            if start > addr:
                missing.append((addr, start))

            addr = start + len(backer)
            if addr >= end:
                break

        return missing

    def _evict_one(self):
        first_key = next(iter(self.lru_order.keys()), None)
        if first_key is None:
            raise Exception("Something has gone horribly wrong")

    def remove_backer(self, start):
        popped = super().remove_backer(start)
        self.resident -= len(popped)
        self.lru_order.pop(start)
        return popped

    def add_backer(self, start, data, overwrite=False):
        if overwrite:
            raise TypeError("Cannot add_backer(overwrite=True) with LazyClemory")
        super().add_backer(start, data)
        self.resident += len(data)
        self.lru_order[start] = None

    def make_resident(self, addr, size):
        if size > self.max_resident:
            raise MemoryError("Cannot hold %#x bytes in memory at once. lol" % size)
        while size > 0:
            region_start, region_size = self.region_containing(addr)
            resident_start = max(region_start, addr & ~(self.chunk_size - 1))
            resident_end = min(((addr + size - 1) & ~(self.chunk_size - 1)) + self.chunk_size, region_start + region_size)

            # annoying fixed-point algorithm. imagine [0, 0x1001] is mapped and you request [0x1000, 0x3000]
            # and the limit is 0x2000. You gotta evict the first mapping.
            while True:
                splitted = self._split_to_unmapped(resident_start, resident_end)
                if not splitted:
                    break
                for real_start, real_end in splitted:
                    while real_end - real_start + self.resident > self._real_max_resident:
                        self._evict_one()
                    self.add_backer(real_start, self.owner._load_data(real_start, real_end - real_start))

            # ensure the stuff that was already resident doesn't get evicted next round
            for start, backer in self.backers(resident_start):
                if start >= resident_end:
                    break
                self.lru_order.move_to_end(start)

            size = addr + size - resident_end
            addr = resident_end

    def load(self, addr, size):
        self.make_resident(addr, size)
        return super().load(addr, size)

    def store(self, addr, data):
        raise TypeError("Cannot store data to LazyClemory")

    def find(self, data, search_min=None, search_max=None):
        raise TypeError("Cannot perform find operation via LazyClemory")


class LazyBackend(Backend):
    """
    This is a set of tools which should help you write a backend which accesses some memory space lazily.
    """
    def __init__(self, binary, arch, entry_point, **kwargs):
        super().__init__(binary, None, arch=arch, entry_point=entry_point, **kwargs)

        self._memory_map = None
        self._segments = None
        self.pic = False
        self.linked_base = 0
        self.memory = LazyClemory(self)

    @property
    def segments(self) -> Regions:
        if self._segments is None:
            self._load_memory_map()
        return self._segments

    def _load_memory_map(self):
        """
        Load the memory map and retain it in self._segments. By default, it will just assume the low half of the address
        space is flat-mapped and rwx.
        """
        memory_map = [(0, 2**(self.arch.bits - 1))]
        self._segments = Regions([NonEmptySegment(addr, size) for addr, size in memory_map])

    CLEMORY_CLASS = LazyClemory

    def _load_data(self, addr: int, size: int):
        raise NotImplementedError
