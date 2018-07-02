import bisect
import struct
import cffi

from .errors import CLEMemoryError

__all__ = ('Clemory',)

# TODO: Further optimization is possible now that the list of backers is sorted


class Clemory(object):

    __slots__ = ('_arch', '_backers', '_updates', '_pointer', '_root', '_cbackers', '_needs_flattening_personal',
                 'consecutive', 'min_addr', 'max_addr', )

    """
    An object representing a memory space. Uses "backers" and "updates" to separate the concepts of loaded and written
    memory and make lookups more efficient.

    Accesses can be made with [index] notation.
    """
    def __init__(self, arch, root=False):
        self._arch = arch
        self._backers = []  # tuple of (start, str)
        self._updates = {}
        self._pointer = 0
        self._root = root

        self._cbackers = [ ]  # tuple of (start, cdata<buffer>)
        self._needs_flattening_personal = True
        self.consecutive = None
        self.min_addr = None
        self.max_addr = None

    def add_backer(self, start, data):
        """
        Adds a backer to the memory.

        :param start:   The address where the backer should be loaded.
        :param data:    The backer itself. Can be either a string or another :class:`Clemory`.
        """
        if not isinstance(data, (bytes, unicode, Clemory)):
            raise TypeError("Data must be a string or a Clemory")
        if start in self:
            raise ValueError("Address %#x is already backed!" % start)
        if isinstance(data, Clemory) and data._root:
            raise ValueError("Cannot add a root clemory as a backer!")
        bisect.insort(self._backers, (start, data))
        self._update_min_max()
        self._needs_flattening_personal = True

    def update_backer(self, start, data):
        if not isinstance(data, (bytes, unicode, Clemory)):
            raise TypeError("Data must be a string or a Clemory")
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._backers[i] = (start, data)
                self._needs_flattening_personal = True
                break
        else:
            raise ValueError("Can't find backer to update")

        self._update_min_max()

    def remove_backer(self, start):
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._backers.pop(i)
                self._needs_flattening_personal = True
                break
        else:
            raise ValueError("Can't find backer to remove")

        self._update_min_max()

    def __iter__(self):
        for start, string in self._backers:
            if isinstance(string, (bytes, unicode)):
                for x in xrange(len(string)):
                    yield start + x
            else:
                for x in string:
                    yield start + x

    def __getitem__(self, k):
        return self.get_byte(k)

    def get_byte(self, k, orig=False):
        if not orig and k in self._updates:
            return self._updates[k]
        else:
            for start, data in self._backers:
                if isinstance(data, (bytes, unicode)):
                    if 0 <= k - start < len(data):
                        return data[k - start]
                elif isinstance(data, Clemory):
                    try:
                        return data.get_byte(k - start, orig=orig)
                    except KeyError:
                        pass
            raise KeyError(k)

    def __setitem__(self, k, v):
        if k not in self:
            raise IndexError(k)
        self._updates[k] = v
        self._needs_flattening_personal = True

    def __contains__(self, k):

        # Fast path
        if self.consecutive:
            return self.min_addr <= k < self.max_addr
        else:
            # Check if this is an empty Clemory instance
            if not self._backers:
                return None
            # Check if it is out of the memory range
            if k < self.min_addr or k >= self.max_addr:
                return False

        try:
            self.get_byte(k)
            return True
        except KeyError:
            return False

    def __getstate__(self):
        s = {
            '_arch': self._arch,
            '_backers': self._backers,
            '_updates': self._updates,
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
        self._updates = s['_updates']
        self._pointer = s['_pointer']
        self._root = s['_root']
        self.consecutive = s['consecutive']
        self.min_addr = s['min_addr']
        self.max_addr = s['max_addr']

        self._cbackers = [ ]
        self._needs_flattening_personal = True

    def read_bytes(self, addr, n, orig=False):
        """
        Read up to `n` bytes at address `addr` in memory and return an array of bytes.

        Reading will stop at the beginning of the first unallocated region found, or when
        `n` bytes have been read.
        """
        b = []
        try:
            for i in range(addr, addr+n):
                b.append(self.get_byte(i, orig=orig))
        except KeyError:
            pass
        return b

    def write_bytes(self, addr, data):
        """
        Write bytes from `data` at address `addr`.
        """
        for i, c in enumerate(data):
            self[addr+i] = c

    def write_bytes_to_backer(self, addr, data):
        """
        Write bytes from `data` at address `addr` to backer instead of self._updates. This is only needed when writing a
        huge amount of data.
        """

        pos = addr
        to_insert = [ ]
        i = 0

        while i < len(self._backers) and data:
            start, backer_data = self._backers[i] # self._backers is always sorted
            size = len(backer_data)
            stop = start + size
            if pos >= start:
                if pos < stop:
                    if pos + len(data) > stop:
                        new_backer_data = backer_data[ : pos - start] + data[ : stop - pos]
                        self._backers[i] = (start, new_backer_data)

                        # slicing data
                        data = data[ stop - pos : ]
                        pos = stop
                    else:
                        new_backer_data = backer_data[ : pos - start] + data + backer_data[pos - start + len(data) : ]
                        self._backers[i] = (start, new_backer_data)
                        # We are done
                        break
                i += 1
            else:
                # Look forward and see if we should insert a new backer
                if i < len(self._backers) - 1:
                    if pos + len(data) <= start:
                        to_insert.append((pos, data[ : start - pos]))

                        data = data[start - pos : ]
                        pos = start

                    else:
                        # we reach the end of our data to insert
                        to_insert.append((pos, data))

                        break
                else:
                    # seems we reach the end of the list...
                    to_insert.append((pos, data))

                    break

        # Insert the blocks that are needed to insert into self._backers
        for seg_start, seg_data in to_insert:
            bisect.insort(self._backers, (seg_start, seg_data))

        # Set the flattening_needed flag
        self._needs_flattening_personal = True

    def read_addr_at(self, where, orig=False):
        """
        Read addr stored in memory as a series of bytes starting at `where`.
        """
        by = ''.join(self.read_bytes(where, self._arch.bytes, orig=orig))
        try:
            return struct.unpack(self._arch.struct_fmt(), by)[0]
        except struct.error:
            raise CLEMemoryError("Not enough bytes at %#x" % where)

    def write_addr_at(self, where, addr):
        """
        Writes `addr` into a series of bytes in memory at `where`.
        """
        by = struct.pack(self._arch.struct_fmt(), addr % (2**self._arch.bits))
        self.write_bytes(where, by)

    @property
    def _stride_repr(self):
        out = []
        for start, data in self._backers:
            if isinstance(data, bytes):
                out.append((start, bytearray(data)))
            elif isinstance(data, unicode):
                out.append((start, map(ord, data)))
            else:
                out += map(lambda (substart, subdata), start=start: (substart+start, subdata), data._stride_repr)
        for key, val in self._updates.iteritems():
            for start, data in out:
                if start <= key < start + len(data):
                    data[key - start] = val
                    break
            else:
                raise ValueError('There was an update to a Clemory not on top of any backer')
        return out

    @property
    def stride_repr(self):
        """
        Returns a representation of memory in a list of (start, end, data) where data is a string.
        """
        return map(lambda (start, bytearr): (start, start+len(bytearr), str(bytearr) if type(bytearr) is bytearray else bytearr), self._stride_repr)

    def seek(self, value):
        """
        The stream-like function that sets the "file's" current position. Use with :func:`read()`.

        :param value:        The position to seek to.
        """
        self._pointer = value

    def read(self, nbytes):
        """
        The stream-like function that reads up to a number of bytes starting from the current
        position and updates the current position. Use with :func:`seek`.

        Up to `nbytes` bytes will be read, halting at the beginning of the first unmapped region
        encountered.
        """
        if nbytes == 1:
            try:
                out = self[self._pointer]
                self._pointer += 1
                return out
            except KeyError:
                return ''
        else:
            out = self.read_bytes(self._pointer, nbytes)
            self._pointer += len(out)
            return ''.join(out)

    def tell(self):
        return self._pointer

    @property
    def cbackers(self):
        """
        This function directly returns a list of already-flattened cbackers. It's designed for performance purpose.
        GirlScout uses it. Use this property at your own risk!
        """
        if self._needs_flattening:
            self._flatten_to_c()

        return self._cbackers

    def _update_min_max(self):
        """
        Update the three properties of Clemory: consecutive, min_addr, and max_addr.

        :return:    None
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

            if isinstance(backer, (bytes, unicode)):
                backer_length = len(backer)
                # Update max_addr
                if start + backer_length > max_addr:
                    max_addr = start + backer_length
                # Update the predicted starting address
                next_start = start + backer_length

            elif isinstance(backer, Clemory):
                if backer.max_addr is not None and backer.min_addr is not None:
                    # Update max_addr
                    if start + backer.max_addr > max_addr:
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

    def _flatten_to_c(self):
        """
        Flattens memory backers to C-backed strings.
        """

        if not self._root:
            raise ValueError("Pulling C data out of a non-root Clemory is disallowed!")

        ffi = cffi.FFI()

        # Considering the fact that there are much less bytes in self._updates than amount of bytes in backer,
        # this way instead of calling self.__getitem__() is actually faster
        strides = self._stride_repr

        self._cbackers = [ ]
        for start, data in strides:
            cbacker = ffi.new("unsigned char [%d]" % len(data), str(data))
            self._cbackers.append((start, cbacker))

    @property
    def _needs_flattening(self):
        """
        WARNING:
        ONLY use this property if you're going to flatten it immediately after seeing a True result
        This is what is expected
        debuggers beware
        """
        out = self._needs_flattening_personal
        for backer in self._backers:
            if isinstance(backer[1], Clemory):
                out |= backer[1]._needs_flattening

        self._needs_flattening_personal = False
        return out

    def read_bytes_c(self, addr):
        """
        Read `n` bytes at address `addr` in cbacked memory, and returns a tuple of a cffi buffer pointer and the
        size of the continuous block bytes starting at `addr`.

        Note: We don't support reading across segments for performance concerns.

        :return: A tuple of a cffi buffer pointer and the maximum size of bytes starting from `addr`.
        :rtype: tuple
        """

        if self._needs_flattening:
            self._flatten_to_c()

        for start, cbacker in self._cbackers:
            cbacker_len = len(cbacker)
            if start <= addr < start + cbacker_len:
                return cbacker + (addr - start), start + cbacker_len - addr

        raise KeyError(addr)
