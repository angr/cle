
import bisect
import struct
from typing import Tuple, Union, List

__all__ = ('Clemory',)


class Clemory:

    __slots__ = ('_arch', '_backers', '_updates', '_pointer', '_root', '_cbackers', '_needs_flattening_personal',
                 'consecutive', 'min_addr', 'max_addr', 'concrete_target' )

    """
    An object representing a memory space.

    Accesses can be made with [index] notation.
    """
    def __init__(self, arch, root=False):
        self._arch = arch
        self._backers = []  # type: Tuple[int, Union[bytearray, Clemory, List[int]]]
        self._pointer = 0
        self._root = root

        self.consecutive = True
        self.min_addr = 0
        self.max_addr = 0

        self.concrete_target = None

    def is_concrete_target_set(self):
        return self.concrete_target is not None

    def set_concrete_target(self, concrete_target):
        self.concrete_target = concrete_target

    def add_backer(self, start, data):
        """
        Adds a backer to the memory.

        :param start:   The address where the backer should be loaded.
        :param data:    The backer itself. Can be either a bytestring or another :class:`Clemory`.
        """
        if not data:
            raise ValueError("Backer is empty!")

        if not isinstance(data, (bytes, list, Clemory)):
            raise TypeError("Data must be a string or a Clemory")
        if start in self:
            raise ValueError("Address %#x is already backed!" % start)
        if isinstance(data, Clemory) and data._root:
            raise ValueError("Cannot add a root clemory as a backer!")
        if type(data) is bytes:
            data = bytearray(data)
        bisect.insort(self._backers, (start, data))
        self._update_min_max()

    def update_backer(self, start, data):
        if not isinstance(data, (bytes, list, Clemory)):
            raise TypeError("Data must be a string or a Clemory")
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

        # concrete memory read
        if self.is_concrete_target_set():
            # l.debug("invoked get_byte %x" % (k))
            return self.concrete_target.read_memory(k, 1)

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
            'concrete_target': self.concrete_target
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
        self.concrete_target = s['concrete_target']

    def backers(self, addr=0):
        """
        Iterate through each backer for this clemory and all its children, yielding tuples of
        ``(start_addr, backer)`` where each backer is a bytearray.

        :param addr:    An optional starting address - all backers before and not including this
                        address will be skipped.
        """
        started = addr <= 0
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

        # concrete memory read
        if self.is_concrete_target_set():
            # l.debug("invoked read_bytes %x %x" % (addr, n))
            return self.concrete_target.read_memory(addr, n)

        views = []

        for start, backer in self.backers(addr):
            if start > addr:
                break
            offset = addr - start
            size = len(backer) - offset
            views.append(memoryview(backer)[offset:offset + n])

            addr += size
            n -= size

            if n <= 0:
                break

        if not views:
            raise KeyError(n)
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

    def unpack(self, addr, fmt):
        """
        Use the ``struct`` module to unpack the data at address `addr` with the format `fmt`.
        """

        try:
            start, backer = next(self.backers(addr))
        except StopIteration:
            raise KeyError(addr)

        if start > addr:
            raise KeyError(addr)

        try:
            return struct.unpack_from(fmt, backer, addr - start)
        except struct.error as e:
            if len(backer) - (addr - start) >= struct.calcsize(fmt):
                raise e
            raise KeyError(addr)

    def unpack_word(self, addr, size=None, signed=False, endness=None):
        """
        Use the ``struct`` module to unpack a single integer from the address `addr`.

        You may override any of the attributes of the word being extracted:

        :param int size:    The size in bytes to pack/unpack. Defaults to wordsize (e.g. 4 bytes on
                            a 32 bit architecture)
        :param bool signed: Whether the data should be extracted signed/unsigned. Default unsigned
        :param str archinfo.Endness: The endian to use in packing/unpacking. Defaults to memory endness
        """
        return self.unpack(addr, self._arch.struct_fmt(size=size, signed=signed, endness=endness))[0]

    def pack(self, addr, fmt, *data):
        """
        Use the ``struct`` module to pack `data` into memory at address `addr` with the format `fmt`.
        """

        try:
            start, backer = next(self.backers(addr))
        except StopIteration:
            raise KeyError(addr)

        if start > addr:
            raise KeyError(addr)

        try:
            return struct.pack_into(fmt, backer, addr - start, *data)
        except struct.error as e:
            if len(backer) - (addr - start) >= struct.calcsize(fmt):
                raise e
            raise KeyError(addr)

    def pack_word(self, addr, data, size=None, signed=False, endness=None):
        """
        Use the ``struct`` module to pack a single integer `data` into memory at the address `addr`.

        You may override any of the attributes of the word being packed:

        :param int size:    The size in bytes to pack/unpack. Defaults to wordsize (e.g. 4 bytes on
                            a 32 bit architecture)
        :param bool signed: Whether the data should be extracted signed/unsigned. Default unsigned
        :param str archinfo.Endness: The endian to use in packing/unpacking. Defaults to memory endness
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

        if self.is_concrete_target_set():
            # l.debug("invoked read %x" % (nbytes))
            return self.concrete_target.read_memory(self._pointer, nbytes)

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

            if isinstance(backer, (bytearray, list)):
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
            else:
                raise TypeError("Unsupported backer type %s." % type(backer))

        self.consecutive = is_consecutive
        self.min_addr = min_addr
        self.max_addr = max_addr
