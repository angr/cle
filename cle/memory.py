import collections

class Clemory(collections.MutableMapping):
    def __init__(self):
        self._storage = { }

    #
    # Methods for the collection
    #

    def __getitem__(self, k):
        return self._storage[k]

    def __setitem__(self, k, v):
        self._storage[k] = v

    def __delitem__(self, k):
        del self._storage[k]

    def __iter__(self):
        return iter(self._storage)

    def __len__(self):
        return len(self._storage)

    def __contains__(self, k):
        return k in self._storage

    def __getstate__(self):
        return { k:ord(v) for k,v in self._storage.iteritems() }

    def __setstate__(self, s):
        for k,v in s.iteritems():
            self._storage[k] = chr(v)

    def read_bytes(self, addr, n):
        """ Read @n bytes at address @addr in memory and return an array of bytes
        """
        b = []
        for i in range(addr, addr+n):
            b.append(self.get(i))
        return b

    def write_bytes(self, addr, data):
        """
        Write bytes from @data at address @addr
        """
        d = {}
        for i in range(0,len(data)):
            d[addr+i] = data[i]
        self.update(d) # This merges d into self

    def read_addr_at(self, addr, archinfo):
        """
        Read addr stored in memory as a serie of bytes starting at @addr
        @archinfo is an cle.Archinfo instance
        """
        return archinfo.bytes_to_addr(''.join(self.read_bytes(addr, archinfo.bits/8)))

    def write_addr_at(self, where, addr, archinfo):
        """
        Writes @addr into a serie of bytes in memory at @where
        @archinfo is an cle.Archinfo instance
        """
        by = archinfo.addr_to_bytes(addr)
        self.write_bytes(where, by)

    @property
    def stride_repr(self):
        # We save tuples of (start, end, bytes) in the list `strides`
        strides = [ ]

        start_ = None
        end_ = None
        bytestring = ""

        mem = self

        for pos in xrange(min(self.keys()), max(self.keys())):
            if pos in mem:
                if start_ is None:
                    start_ = pos
                end_ = pos

                bytestring += mem[pos]
            else:
                if len(bytestring):
                    # Create the tuple and save it
                    tpl = (start_, end_, bytestring)
                    strides.append(tpl)

                    # Initialize the data structure
                    start_ = None
                    end_ = None
                    bytestring = ""

        if start_ is not None:
            tpl = (start_, end_, bytestring)
            strides.append(tpl)

        return strides
