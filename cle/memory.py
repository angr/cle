import bisect
import struct
from mmap import mmap
from typing import Tuple, Union, List

import archinfo

__all__ = ('ClemoryBase', 'Clemory', 'ClemoryView')


class ClemoryBase:
    __slots__ = ('_arch', '_pointer')
    def __init__(self, arch):
        self._arch = arch
        self._pointer = 0

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

    def backers(self, addr=0):
        raise NotImplementedError

    def find(self, data, search_min=None, search_max=None):
        raise NotImplementedError

    def unpack(self, addr, fmt):
        """
        Use the ``struct`` module to unpack the data at address `addr` with the format `fmt`.
        """

        try:
            start, backer = next(self.backers(addr))
        except StopIteration:
            raise KeyError(addr) # pylint: disable=raise-missing-from

        if start > addr:
            raise KeyError(addr)

        try:
            return struct.unpack_from(fmt, backer, addr - start)
        except struct.error as e:
            if len(backer) - (addr - start) >= struct.calcsize(fmt):
                raise e
            raise KeyError(addr) # pylint: disable=raise-missing-from

    def unpack_word(self, addr, size=None, signed=False, endness=None):
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
                raise ValueError("Unsupported endness value %s." % endness)

            lo = self.unpack_word(addr + lo_off, size=subsize, signed=False, endness=endness)
            hi = self.unpack_word(addr + hi_off, size=subsize, signed=signed, endness=endness)
            return (hi << (subsize << 3)) | lo

        return self.unpack(addr, self._arch.struct_fmt(size=size, signed=signed, endness=endness))[0]

    def pack(self, addr, fmt, *data):
        """
        Use the ``struct`` module to pack `data` into memory at address `addr` with the format `fmt`.
        """

        try:
            start, backer = next(self.backers(addr))
        except StopIteration:
            raise KeyError(addr) # pylint: disable=raise-missing-from

        if start > addr:
            raise KeyError(addr) # pylint: disable=raise-missing-from

        try:
            return struct.pack_into(fmt, backer, addr - start, *data)
        except struct.error as e:
            if len(backer) - (addr - start) >= struct.calcsize(fmt):
                raise e
            raise KeyError(addr) # pylint: disable=raise-missing-from

    def pack_word(self, addr, data, size=None, signed=False, endness=None):
        """
        Use the ``struct`` module to pack a single integer `data` into memory at the address `addr`.

        You may override any of the attributes of the word being packed:

        :param int size:    The size in bytes to pack/unpack. Defaults to wordsize (e.g. 4 bytes on
                            a 32 bit architecture)
        :param bool signed: Whether the data should be extracted signed/unsigned. Default unsigned
        :param archinfo.Endness endness: The endian to use in packing/unpacking. Defaults to memory endness
        """
        if not signed:
            data &= (1 << (size*8 if size is not None else self._arch.bits)) - 1
        return self.pack(addr, self._arch.struct_fmt(size=size, signed=signed, endness=endness), data)

    def read(self, nbytes):
        """
        The stream-like function that reads up to a number of bytes starting from the current
        position and updates the current position. Use with :func:`seek`.

        Up to `nbytes` bytes will be read, halting at the beginning of the first unmapped region
        encountered.
        """

        try:
            out = self.load(self._pointer, nbytes)
        except KeyError:
            return b''
        else:
            self._pointer += len(out)
            return out

    def seek(self, value):
        """
        The stream-like function that sets the "file's" current position. Use with :func:`read()`.

        :param value:        The position to seek to.
        """
        self._pointer = value

    def tell(self):
        return self._pointer

    def close(self):  # pylint: disable=no-self-use
        pass

class Clemory(ClemoryBase):
    """
    An object representing a memory space.

    Accesses can be made with [index] notation.
    """

    __slots__ = ('_backers', '_root', 'consecutive', 'min_addr', 'max_addr')

    def __init__(self, arch, root=False):
        super().__init__(arch)
        self._backers = []  # type: List[Tuple[int, Union[bytearray, Clemory, List[int]]]]
        self._root = root
        self.consecutive = True
        self.min_addr = 0
        self.max_addr = 0

    def add_backer(self, start, data, overwrite=False):
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

        if not isinstance(data, (bytes, bytearray, list, Clemory, mmap)):
            raise TypeError("Data must be a bytes, list, or Clemory object.")
        if overwrite:
            if isinstance(data, Clemory):
                raise TypeError("Cannot perform an overwrite-add with a Clemory")
            self.split_backer(start)
            self.split_backer(start + len(data))
            try:
                self.remove_backer(start)
            except ValueError:
                pass
            try:
                existing, _ = next(self.backers(start + len(data)))
            except StopIteration:
                pass
            else:
                if existing < start + len(data):
                    self.remove_backer(existing)
        else:
            try:
                existing, _ = next(self.backers(start))
            except StopIteration:
                pass
            else:
                if existing <= start:
                    raise ValueError("Address %#x is already backed!" % start)
        if isinstance(data, Clemory) and data._root:
            raise ValueError("Cannot add a root clemory as a backer!")
        if type(data) is bytes:
            data = bytearray(data)
        bisect.insort(self._backers, (start, data))
        self._update_min_max()

    def split_backer(self, addr):
        """
        Ensures that ``addr`` is the start of a backer, if it is backed.
        """
        try:
            start_addr, backer = next(self.backers(addr))
        except StopIteration:
            return
        if addr <= start_addr:
            return
        if isinstance(backer, ClemoryBase):
            raise ValueError("Cannot split a backer which is itself a clemory")
        if addr >= start_addr + len(backer):
            return

        self.remove_backer(start_addr)
        self.add_backer(start_addr, backer[:addr - start_addr])
        self.add_backer(addr, backer[addr - start_addr:])

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} [{hex(self.min_addr)}:{hex(self.max_addr)}]>"

    def update_backer(self, start, data):
        if not isinstance(data, (bytes, list, Clemory)):
            raise TypeError("Data must be a bytes, list, or Clemory object.")
        if type(data) is bytes:
            data = bytearray(data)
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._backers[i] = (start, data)
                break
        else:
            raise ValueError("Can't find backer to update")

        self._update_min_max()

    def remove_backer(self, start):
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._backers.pop(i)
                break
        else:
            raise ValueError("Can't find backer to remove")

        self._update_min_max()

    def __iter__(self):
        for start, string in self._backers:
            if isinstance(string, (bytes, list)):
                for x in range(len(string)):
                    yield start + x
            else:
                for x in string:
                    yield start + x

    def __getitem__(self, k):
        for start, data in self._backers:
            if type(data) in (bytearray, list):
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
            if type(data) in (bytearray, list):
                if 0 <= k - start < len(data):
                    data[k - start] = v
                    return
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
            '_arch': self._arch,
            '_backers': self._backers,
            '_pointer': self._pointer,
            '_root': self._root,
            'consecutive': self.consecutive,
            'min_addr': self.min_addr,
            'max_addr': self.max_addr,
        }

        return s

    def __setstate__(self, s):
        self._arch = s['_arch']
        self._backers = s['_backers']
        self._pointer = s['_pointer']
        self._root = s['_root']
        self.consecutive = s['consecutive']
        self.min_addr = s['min_addr']
        self.max_addr = s['max_addr']

    def backers(self, addr=0):
        """
        Iterate through each backer for this clemory and all its children, yielding tuples of
        ``(start_addr, backer)`` where each backer is a bytearray.

        :param addr:    An optional starting address - all backers before and not including this
                        address will be skipped.
        """
        started = False
        for start, backer in self._backers:
            if not started:
                end = start + backer.max_addr if type(backer) is Clemory else start + len(backer)
                if addr >= end:
                    continue
                started = True
            if type(backer) is Clemory:
                for s, b in backer.backers(addr - start):
                    yield s + start, b
            else:
                yield start, backer

    def load(self, addr, n):
        """
        Read up to `n` bytes at address `addr` in memory and return a bytes object.

        Reading will stop at the beginning of the first unallocated region found, or when
        `n` bytes have been read.
        """
        views = []

        for start, backer in self.backers(addr):
            if start > addr:
                break
            offset = addr - start
            if not views and offset + n < len(backer):
                return bytes(memoryview(backer)[offset:offset + n])
            size = len(backer) - offset
            views.append(memoryview(backer)[offset:offset + n])

            addr += size
            n -= size

            if n <= 0:
                break

        if not views:
            raise KeyError(addr)
        return b''.join(views)

    def store(self, addr, data):
        """
        Write bytes from `data` at address `addr`.

        Note: If the store runs off the end of a backer and into unbacked space, this function
        will update the backer but also raise ``KeyError``.
        """
        for start, backer in self.backers(addr):
            if start > addr:
                raise KeyError(addr)
            offset = addr - start
            size = len(backer) - offset
            backer[offset:offset + len(data)] = data if len(data) <= size else data[:size]

            addr += size
            data = data[size:]

            if not data:
                break

        if data:
            raise KeyError(addr)

    def find(self, data, search_min=None, search_max=None):
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
            if type(backer) is Clemory:
                if search_max < backer.min_addr + start or search_min > backer.max_addr + start:
                    continue
                yield from (addr + start for addr in backer.find(data, search_min-start, search_max-start))
            elif type(backer) is list:
                raise TypeError("find is not supported for list-backed clemories")
            else:
                if search_max < start or search_min > start + len(data):
                    continue
                ptr = search_min - start - 1
                while True:
                    ptr += 1
                    ptr = backer.find(data, ptr)
                    if ptr == -1 or ptr + len(data) > search_max - start - 1:
                        break
                    yield ptr + start

    def _update_min_max(self):
        """
        Update the three properties of Clemory: consecutive, min_addr, and max_addr.
        """

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

            if isinstance(backer, (bytearray, list, mmap)):
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
                raise TypeError("Unsupported backer type %s." % type(backer))

        self.consecutive = is_consecutive
        self.min_addr = min_addr
        self.max_addr = max_addr


class ClemoryView(ClemoryBase):
    def __init__(self, backer, start, end, offset=0):
        """
        A Clemory which presents a subset of another Clemory as an address space

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

    def __getitem__(self, k):
        if not self._offset <= k < self._endoffset:
            raise KeyError(k)
        return self._backer[k + self._rebase]

    def __setitem__(self, k, v):
        if not self._offset <= k < self._endoffset:
            raise KeyError(k)
        return self._backer[k + self._rebase]

    def __contains__(self, k):
        if not self._offset <= k < self._endoffset:
            raise KeyError(k)
        return k + self._rebase in self._backer

    def backers(self, addr=0):
        for oaddr, backer in self._backer.backers(addr=addr + self._rebase):
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
            return b''
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

    def find(self, data, search_min=None, search_max=None):
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

    def backers(self, addr=0):
        raise TypeError("Cannot access backers through address translation")

    def find(self, data, search_min=None, search_max=None):
        raise TypeError("Cannot perform finds through address translation")
