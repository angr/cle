import logging
l = logging.getLogger("cle.concrete_memory")
class ConcreteClemory(object):

    def __init__(self, concrete_target):
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
        l.debug("invoked get_byte %s"%(addr))
        return self.concrete_target.read_memory(addr,1)

    def read_bytes(self, addr, nbytes):
        """
        read nbytes bytes at address addr
        :param addr: address to read
        :param nbytes: number of bytes to read
        :return: list of characters (str) containing the memory at address addr
        :rtype: list of str
        """
        l.debug("invoked read_bytes %s %s"%(addr,nbytes))
        return list(self.concrete_target.read_memory(addr,nbytes))

    def read_addr_at(self, where, orig=False):
        """
        Read addr stored in memory as a series of bytes starting at `where`.
        """
        l.debug("invoked read_addr_at %s"%(where))
        raise NotImplementedError("to implement problem: 2 differente archs objects Avatar and Angr")

    def seek(self, value):
        """
        The stream-like function that sets the "file's" current position. Use with :func:`read()`.
        :param value:        The position to seek to.
        """
        l.debug("invoked seek_at %s"%(value))
        self._pointer = value

    def read(self, nbytes):
        """
        The stream-like function that reads up to a number of bytes starting from the current
        position and updates the current position. Use with :func:`seek`.

        Up to `nbytes` bytes will be read
        """
        l.debug("invoked read %s"%(nbytes))
        return self.concrete_target.read_memory(self._pointer, nbytes)




