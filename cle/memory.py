import bisect
import struct
import cffi

__all__ = ('Clemory',)

# TODO: Further optimization is possible now that the list of backers is sorted

class Clemory(object):
    """
    An object representing a memory space. Uses "backers" and "updates"
    to separate the concepts of loaded and written memory and make
    lookups more efficient.

    Accesses can be made with [index] notation.
    """
    def __init__(self, arch, root=False):
        self._arch = arch
        self._backers = []  # tuple of (start, str)
        self._updates = {}
        self._pointer = 0
        self._root = root

        self._cbackers = [ ] # tuple of (start, cdata<buffer>)
        self._needs_flattening_personal = True

    def add_backer(self, start, data):
        """
        Adds a backer to the memory.

        @param start        The address where the backer should be loaded
        @param data         The backer itself. Can be either a string or another Clemory
        """
        if not isinstance(data, (str, Clemory)):
            raise TypeError("Data must be a string or a Clemory")
        if start in self:
            raise ValueError("Address %#x is already backed!" % start)
        if isinstance(data, Clemory) and data._root:
            raise ValueError("Cannot add a root clemory as a backer!")
        bisect.insort(self._backers, (start, data))
        self._needs_flattening_personal = True

    def update_backer(self, start, data):
        if not isinstance(data, (str, Clemory)):
            raise TypeError("Data must be a string or a Clemory")
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._backers[i] = (start, data)
                self._needs_flattening_personal = True
                break
        else:
            raise ValueError("Can't find backer to update")

    def remove_backer(self, start):
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._backers.pop(i)
                self._needs_flattening_personal = True
                break
        else:
            raise ValueError("Can't find backer to remove")

    def __iter__(self):
        for start, string in self._backers:
            if isinstance(string, str):
                for x in xrange(len(string)):
                    yield start + x
            else:
                for x in string:
                    yield start + x

    def __getitem__(self, k):
        if k in self._updates:
            return self._updates[k]
        else:
            for start, data in self._backers:
                if isinstance(data, str):
                    if 0 <= k - start < len(data):
                        return data[k - start]
                elif isinstance(data, Clemory):
                    try:
                        return data[k - start]
                    except KeyError:
                        pass
            raise KeyError(k)

    def __setitem__(self, k, v):
        if k not in self:
            raise IndexError(k)
        self._updates[k] = v
        self._needs_flattening_personal = True

    def __contains__(self, k):
        try:
            self.__getitem__(k)
            return True
        except KeyError:
            return False

    def __getstate__(self):
        self._cbackers = [ ]
        self._needs_flattening_personal = True
        return self.__dict__

    def __setstate__(self, data):
        self.__dict__.update(data)

    def read_bytes(self, addr, n):
        """ Read @n bytes at address @addr in memory and return an array of bytes
        """
        b = []
        for i in range(addr, addr+n):
            b.append(self[i])
        return b

    def write_bytes(self, addr, data):
        """
        Write bytes from @data at address @addr
        """
        for i, c in enumerate(data):
            self[addr+i] = c

    def write_bytes_to_backer(self, addr, data):
        """
        Write bytes from @data at address @addr to backer instead of self._updates
        This is only needed when writing a huge amount of data
        """

        pos = addr
        to_insert = [ ]
        i = 0

        while i < len(self._backers) and len(data):
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

    def read_addr_at(self, where):
        """
        Read addr stored in memory as a serie of bytes starting at @where
        """
        return struct.unpack(self._arch.struct_fmt(), ''.join(self.read_bytes(where, self._arch.bytes)))[0]

    def write_addr_at(self, where, addr):
        """
        Writes @addr into a serie of bytes in memory at @where
        @archinfo is an cle.Archinfo instance
        """
        by = struct.pack(self._arch.struct_fmt(), addr % (2**self._arch.bits))
        self.write_bytes(where, by)

    @property
    def _stride_repr(self):
        out = []
        for start, data in self._backers:
            if isinstance(data, str):
                out.append((start, bytearray(data)))
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
        Returns a representation of memory in a list of (start, end, data)
        where data is a string.
        """
        return map(lambda (start, bytearr): (start, start+len(bytearr), str(bytearr)), self._stride_repr)

    def seek(self, value):
        """
        The stream-like function that sets the "file's" current position.
        Use with read().

        @param value        The position to seek to
        """
        self._pointer = value

    def read(self, nbytes):
        """
        The stream-like function that reads a number of bytes starting from the
        current position and updates the current position. Use with seek().

        @param nbytes   The number of bytes to read
        """
        if nbytes == 1:
            self._pointer += 1
            return self[self._pointer-1]
        else:
            out = self.read_bytes(self._pointer, nbytes)
            self._pointer += nbytes
            return ''.join(out)

    @property
    def cbackers(self):
        """
        This function directly returns a list of already-flattened cbackers. It's designed for performance purpose.
        GirlScout uses it. Use this property at your own risk!
        """
        if self._needs_flattening:
            self._flatten_to_c()

        return self._cbackers

    def _flatten_to_c(self):
        """
        Flattens memory backers to C-backed strings
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
        out = self._needs_flattening_personal
        for backer in self._backers:
            if isinstance(backer, Clemory):
                out |= backer._needs_flattening

        self._needs_flattening_personal = False
        return out


    def read_bytes_c(self, addr):
        """
        Read @n bytes at address @addr in cbacked memory, and returns a cffi buffer pointer.
        Note: We don't support reading across segments for performance concerns.
        """

        if self._needs_flattening:
            self._flatten_to_c()

        for start, cbacker in self._cbackers:
            if addr >= start and addr < start + len(cbacker):
                return cbacker + (addr - start), start + len(cbacker) - addr

        raise KeyError(addr)
