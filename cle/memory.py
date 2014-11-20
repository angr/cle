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
