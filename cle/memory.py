class Clemory(object):
    def __init__(self, archinfo):
        self._archinfo = archinfo
        self._backers = []  # tuple of (start, str)
        self._updates = {}
        self._pointer = 0

    def add_backer(self, start, data):
        self._backers.append((start, data))

    def update_backer(self, start, data):
        for i, (oldstart, _) in enumerate(self._backers):
            if oldstart == start:
                self._updates[i] = (start, data)
                break

    def __getitem__(self, k):
        if k in self._updates:
            return self._updates[k]
        else:
            for start, data in reversed(self._backers):
                if isinstance(data, str):
                    if 0 <= k - start < len(data):
                        return data[k - start]
                elif isinstance(data, (Clemory, dict)):
                    try:
                        return data[k - start]
                    except KeyError:
                        pass
            raise KeyError(k)

    def __setitem__(self, k, v):
        self._updates[k] = v

    # no __delitem__, __iter__, or __len__: not clear how that would work w/ backers

    def __contains__(self, k):
        try:
            self.__getitem__(k)
            return True
        except KeyError:
            return False

    def __getstate__(self):
        out = { 'updates': {k:ord(v) for k,v in self._updates.iteritems()}, 'backers': [] }
        for start, data in self._backers:
            if isinstance(data, str):
                out['backers'].append((start, {'type': 'str', 'data': data}))
            elif isinstance(data, dict):
                out['backers'].append((start, {'type': 'dict', 'data': data}))
            elif isinstance(data, Clemory):
                out['backers'].append((start, {'type': 'Clemory', 'data': data.__getstate__()}))

    def __setstate__(self, s):
        self._updates = {k:chr(v) for k,v in s['updates'].iteritems()}
        self._backers = []
        for start, serialdata in s['backers']:
            if serialdata['type'] == 'str':
                self._backers.append((start, serialdata['data']))
            elif serialdata['type'] == 'dict':
                self._backers.append((start, serialdata['data']))
            elif serialdata['type'] == 'Clemory':
                subdata = Clemory(self._archinfo)
                subdata.__setstate__(serialdata['data'])
                self._backers.append((start, subdata))

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

    def read_addr_at(self, where):
        """
        Read addr stored in memory as a serie of bytes starting at @addr
        @archinfo is an cle.Archinfo instance
        """
        return self._archinfo.bytes_to_addr(''.join(self.read_bytes(where, self._archinfo.bits/8)))

    def write_addr_at(self, where, addr):
        """
        Writes @addr into a serie of bytes in memory at @where
        @archinfo is an cle.Archinfo instance
        """
        by = self._archinfo.addr_to_bytes(addr)
        self.write_bytes(where, by)

    #@property
    #def stride_repr(self):
    #    # We save tuples of (start, end, bytes) in the list `strides`
    #    strides = [ ]

    #    start_ = None
    #    end_ = None
    #    bytestring = ""

    #    mem = self

    #    for pos in xrange(min(self.keys()), max(self.keys())):
    #        if pos in mem:
    #            if start_ is None:
    #                start_ = pos
    #            end_ = pos

    #            bytestring += mem[pos]
    #        else:
    #            if len(bytestring):
    #                # Create the tuple and save it
    #                tpl = (start_, end_, bytestring)
    #                strides.append(tpl)

    #                # Initialize the data structure
    #                start_ = None
    #                end_ = None
    #                bytestring = ""

    #    if start_ is not None:
    #        tpl = (start_, end_, bytestring)
    #        strides.append(tpl)

    #    return strides

    def seek(self, value):
        self._pointer = value

    def read(self, nbytes):
        if nbytes == 1:
            self._pointer += 1
            return self[self._pointer-1]
        else:
            out = self.read_bytes(self._pointer, nbytes)
            self._pointer += nbytes
            return ''.join(out)
