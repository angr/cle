from __future__ import annotations

import struct

from cle.memory import Clemory


class CryptSentinel(Clemory):
    """
    Mach-O binaries are often encrypted, and some area of memory is only decrypted at runtime later in the loading
    process. This decryption process can't easily be implemented in CLE and is typically done with separate tools
    But not all data is encrypted, and various metadata is still accessible.

    This Clemory serves as a shim that allows us to notice accesses to encrypted areas of memory and raise an exception
    This means that all code that was written will loudly fail on access to encrypted memory, instead of silently
    reading garbage data.
    """

    def __init__(self, arch, root=False):
        super().__init__(arch, root)
        self._crypt_start = None
        self._crypt_end = None
        self._is_encrypted: bool = False

    def __iter__(self):
        if self._is_encrypted:
            raise EncryptedDataAccessException("Cannot iterate encrypted memory region", self._crypt_start)
        return super().__iter__()

    def __getitem__(self, k):
        self._assert_unencrypted_access(k, 1)
        return super().__getitem__(k)

    def __setitem__(self, k, v):
        self._assert_unencrypted_access(k, 1)
        return super().__setitem__(k, v)

    def __contains__(self, k):
        try:
            return super().__contains__(k)
        except EncryptedDataAccessException:
            # Clemory.__contains__ probes __getitem__ when the memory is not consecutive, and that
            # probe goes through the guard above. Whether an address is mapped is a question about
            # the memory map rather than about the bytes, so answer it with a read that skips the
            # guard and discards the byte.
            try:
                Clemory.__getitem__(self, k)
            except KeyError:
                return False
            return True

    def __getstate__(self):
        s = super().__getstate__()
        s["_crypt_start"] = self._crypt_start
        s["_crypt_end"] = self._crypt_end
        s["_is_encrypted"] = self._is_encrypted
        return s

    def __setstate__(self, s):
        super().__setstate__(s)
        self._crypt_start = s.get("_crypt_start")
        self._crypt_end = s.get("_crypt_end")
        self._is_encrypted = s.get("_is_encrypted", False)

    def load(self, addr, n):
        self._assert_unencrypted_access(addr, n)
        return super().load(addr, n)

    def store(self, addr, data):
        self._assert_unencrypted_access(addr, len(data))
        return super().store(addr, data)

    def unpack(self, addr, fmt):
        self._assert_unencrypted_access(addr, struct.calcsize(fmt))
        return super().unpack(addr, fmt)

    def pack(self, addr, fmt, *data):
        self._assert_unencrypted_access(addr, struct.calcsize(fmt))
        return super().pack(addr, fmt, *data)

    def find(self, data, search_min=None, search_max=None):
        if self._is_encrypted:
            raise EncryptedDataAccessException("Cannot search encrypted memory region", self._crypt_start)
        return super().find(data, search_min, search_max)

    def set_crypt_info(self, cryptid, start, size):
        self._is_encrypted = cryptid != 0 and size > 0
        self._crypt_start = start
        self._crypt_end = start + size

    def backers(self, addr=0):
        if self._is_encrypted:
            if self._crypt_start <= addr < self._crypt_end:
                raise EncryptedDataAccessException("Accessing encrypted memory region", addr)
        return super().backers(addr)

    def _assert_unencrypted_access(self, addr, size):
        """
        Make sure that the access does not cover encrypted memory regions
        If it does, raise an error

        The access covers the half-open interval [addr, addr + size), so it overlaps the encrypted
        region when it starts before the region ends and ends after the region starts.

        :param addr:
        :param size:
        :return:
        """
        if not self._is_encrypted:
            return

        if size > 0 and addr < self._crypt_end and addr + size > self._crypt_start:
            raise EncryptedDataAccessException("Accessing encrypted memory region", addr)


class EncryptedDataAccessException(Exception):
    """
    Special exception to be raised when access to encrypted memory is attempted
    """

    def __init__(self, message, addr):
        super().__init__(message)
        self.addr = addr
