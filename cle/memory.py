class Clemory(dict):

    def read_bytes(self, addr, n):
        """ Read @n bytes at address @addr in memory and return an array of bytes
        """
        b = []
        for i in range(addr, addr+n):
            b.append(self.get(i))
        return b
