class Clemory(dict):

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
        bytes = ""

        mem = self

        for pos in xrange(min(self.keys()), max(self.keys())):
            if pos in mem:
                if start_ is None:
                    start_ = pos
                end_ = pos

                bytes += mem[pos]
            else:
                # Create the tuple and save it
                tpl = (start_, end_, bytes)
                strides.append(tpl)

                # Initialize the data structure
                start_ = None
                end_ = None
                bytes = ""

        if start_ is not None:
            tpl = (start_, end_, bytes)
            strides.append(tpl)

        return strides
