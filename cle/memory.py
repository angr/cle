import bisect
import struct
import cffi
import logging
l = logging.getLogger("cle.memory")


__all__ = ('Clemory','SimulatedClemory','ConcreteClemory')


class Clemory(object):
    """
    An object representing a memory space. Uses "backers" and "updates" to separate the concepts of loaded and written
    memory and make lookups more efficient.

    Accesses can be made with [index] notation.
    """
    def __init__(self, arch, root=False):
        self.simulated_clemory = SimulatedClemory(arch,root)
        self.concrete_clemory = None
        self.simulated_addresses = None


    def set_concrete_target(self, concrete_target):
        self.concrete_clemory = ConcreteClemory(concrete_target)

    def set_simulated_addresses(self, simulated_addresses):
        self.simulated_addresses = simulated_addresses


    """
        handle the case in which the read is overlapping between concreted and simulated 
        NOT CORRECTLY handled now since we check only if the start address belongs to the simulated memory
    """
    def _is_address_in_simulated_memory(self,addr):
        #index = bisect.bisect(self.sorted_start_addresses,addr)
        #if index and addr in self.addresses_blacklist
        for start_addr,end_addr in self.simulated_addresses:
            if start_addr < addr < end_addr:
                return True
        return False

    def add_backer(self, start, data):
        return self.get_current_clemory(start).add_backer(start,data)


    def update_backer(self, start, data):
        return self.get_current_clemory(start).update_backer(start,data)



    def remove_backer(self, start):
        return self.get_current_clemory(start).remove_backer(start)

    def get_current_clemory(self,addr=None):
        """
        Identify the correct Clemory object to use. If a concrete clemory object is defined and the address is not in the simulated_addresses
        list the read will be performed in the concrete process otherwise it will be redirected to the ANGR memory
        :param addr:
        :return:
        """
        if self.concrete_clemory is  None:
            return self.simulated_clemory

        elif self._is_address_in_simulated_memory(addr):
            return self.simulated_clemory

        else:
            return self.concrete_clemory


    def __iter__(self):
        self.get_current_clemory().__iter__()


    def __getitem__(self, k):
        return self.get_current_clemory(k).__getitem__(k)

    def get_byte(self, k, orig=False):
        return self.get_current_clemory(k).get_byte(k,orig)

    def __setitem__(self, k, v):
        return self.get_current_clemory(k).__setitem__(k, v)


    def __contains__(self, k):
        return self.get_current_clemory(k).__contains__(k)


    def __getstate__(self):
        return self.get_current_clemory().__getstate__()


    def __setstate__(self, data):
        return self.get_current_clemory().__getstate__(data)

    def read_bytes(self, addr, n, orig=False):
        return self.get_current_clemory(addr).read_bytes(addr,n,orig)


    def write_bytes(self, addr, data):
        return self.get_current_clemory(addr).write_bytes(addr,data)



    def write_bytes_to_backer(self, addr, data):
        return self.get_current_clemory(addr).write_bytes_to_backer(addr, data)

    def read_addr_at(self, where, orig=False):
        return self.get_current_clemory(where).read_addr_at(where,orig)



    def write_addr_at(self, where, addr):
        return self.get_current_clemory(where).write_addr_at(where,addr)



    @property
    def stride_repr(self):
        if self.concrete_clemory is  None:
            return self.simulated_clemory.cbackers
        else:
            return self.concrete_clemory.cbackers




    def seek(self, value):
        return self.get_current_clemory().seek(value)


    def read(self, nbytes):
        return self.get_current_clemory().read(nbytes)

    def tell(self):
        return self.get_current_clemory().tell()


    @property
    def cbackers(self):
        if self.concrete_clemory is  None:
            return self.simulated_clemory.cbackers
        else:
            return self.concrete_clemory.cbackers


    def read_bytes_c(self, addr):
        return self.get_current_clemory().read_bytes_c(addr)




# TODO: Further optimization is possible now that the list of backers is sorted

class SimulatedClemory(object):
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

        self._cbackers = [ ] # tuple of (start, cdata<buffer>)
        self._needs_flattening_personal = True




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
        return struct.unpack(self._arch.struct_fmt(), by)[0]

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
            if addr >= start and addr < start + len(cbacker):
                return cbacker + (addr - start), start + len(cbacker) - addr

        raise KeyError(addr)




class ConcreteClemory(object):

    def __init__(self, concrete_target):
        """
        :param concrete_target:
        :param addresses_blacklist:  list containing tuples (start_address, end_address) that won't be read in the concrete memory but in the ANGR one
        """
        self.concrete_target = concrete_target
        self._pointer = 0




    def __getitem__(self, k):
        return self.get_byte(k)




    def get_byte(self, addr):
        """
        get the byte value at address addr
        :param addr: address to read
        :return: value of the byte
        :rtype: str
        """
        l.debug("invoked get_byte %x"%(addr))
        return self.concrete_target.read_memory(addr,1)

    def read_bytes(self, addr, nbytes):
        """
        read nbytes bytes at address addr
        :param addr: address to read
        :param nbytes: number of bytes to read
        :return: list of characters (str) containing the memory at address addr
        :rtype: list of str
        """
        l.debug("invoked read_bytes %x %x"%(addr,nbytes))
        return list(self.concrete_target.read_memory(addr,nbytes))

    def read_addr_at(self, where, orig=False):
        """
        Read addr stored in memory as a series of bytes starting at `where`.
        """
        l.debug("invoked read_addr_at %x"%(where))
        raise NotImplementedError("to implement problem: 2 differente archs objects Avatar and Angr")

    def seek(self, value):
        """
        The stream-like function that sets the "file's" current position. Use with :func:`read()`.
        :param value:        The position to seek to.
        """
        l.debug("invoked seek_at %x"%(value))
        self._pointer = value

    def read(self, nbytes):
        """
        The stream-like function that reads up to a number of bytes starting from the current
        position and updates the current position. Use with :func:`seek`.

        Up to `nbytes` bytes will be read
        """
        l.debug("invoked read %x"%(nbytes))
        return self.concrete_target.read_memory(self._pointer, nbytes)

    def __setitem__(self, k, v):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def __contains__(self, k):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def __getstate__(self):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def __setstate__(self, data):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def __iter__(self):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def read_bytes_c(self, addr):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def stride_repr(self):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def write_addr_at(self, where, addr):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    @property
    def cbackers(self):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    @property
    def stride_repr(self):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def update_backer(self, start, data):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def write_bytes(self, addr, data):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def write_bytes_to_backer(self, addr, data):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def add_backer(self, start, data):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def update_backer(self, start, data):
        raise NotImplementedError("Method not supported in the ConcreteClemory")

    def remove_backer(self, start ):
        raise NotImplementedError("Method not supported in the ConcreteClemory")








