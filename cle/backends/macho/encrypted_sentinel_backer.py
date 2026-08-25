from __future__ import annotations

from collections.abc import Iterator
from mmap import mmap

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
        self._crypt_start: int | None = None
        self._crypt_end: int | None = None
        self._is_encrypted: bool = False

    def _effective_crypt_interval(self) -> tuple[int, int] | None:
        if not self._is_encrypted:
            return None
        assert self._crypt_start is not None
        assert self._crypt_end is not None
        return self._crypt_start, self._crypt_end

    def load(self, addr, n):
        self._assert_unencrypted_access(addr, n)
        interval = self._effective_crypt_interval()
        if n == 0 and interval is not None and interval[0] <= addr < interval[1]:
            try:
                start, backer, _ = next(super()._backers_with_owners(addr))
            except StopIteration:
                raise KeyError(addr)  # pylint: disable=raise-missing-from
            if start > addr:
                raise KeyError(addr)
            if isinstance(backer, list):
                raise TypeError("Can't load bytes from Clemory backed by list[int]")
            return b""
        return super().load(addr, n)

    def __getitem__(self, addr):
        self._assert_unencrypted_access(addr, 1)
        return super().__getitem__(addr)

    def __setitem__(self, addr, value):
        self._assert_unencrypted_access(addr, 1)
        return super().__setitem__(addr, value)

    def store(self, addr, data):
        self._assert_unencrypted_access(addr, len(data))
        interval = self._effective_crypt_interval()
        if not data and interval is not None and interval[0] <= addr < interval[1]:
            try:
                start, backer, _ = next(super()._backers_with_owners(addr))
            except StopIteration:
                raise KeyError(addr)  # pylint: disable=raise-missing-from
            if not start <= addr < start + len(backer):
                raise KeyError(addr)
            return None
        return super().store(addr, data)

    def find(self, data, search_min=None, search_max=None):
        interval = self._effective_crypt_interval()
        if interval is not None:
            raise EncryptedDataAccessException("Cannot search encrypted memory region", interval[0])
        return super().find(data, search_min, search_max)

    def set_crypt_info(self, cryptid: int, start: int, size: int) -> None:
        old_interval = self._effective_crypt_interval()
        self._is_encrypted = cryptid != 0 and size > 0
        self._crypt_start = start
        self._crypt_end = start + size
        if self._effective_crypt_interval() != old_interval:
            self._semantic_change(structural=True)

    def __getstate__(self):
        state = super().__getstate__()
        state.update(
            {
                "crypt_start": self._crypt_start,
                "crypt_end": self._crypt_end,
                "is_encrypted": self._is_encrypted,
            }
        )
        return state

    def __setstate__(self, state) -> None:
        super().__setstate__(state)
        self._crypt_start = state.get("crypt_start")
        self._crypt_end = state.get("crypt_end")
        self._is_encrypted = state.get("is_encrypted", False)

    def _backers_with_owners_for_reading(
        self, addr=0
    ) -> Iterator[tuple[int, bytes | bytearray | memoryview | mmap | list[int], Clemory]]:
        interval = self._effective_crypt_interval()
        if interval is not None and interval[0] <= addr < interval[1]:
            raise EncryptedDataAccessException("Accessing encrypted memory region", addr)

        for start, backer, owner in super()._backers_with_owners_for_reading(addr):
            end = start + len(backer)
            if interval is None or end <= interval[0] or start >= interval[1]:
                yield start, backer, owner
                continue

            if start < interval[0] and addr < interval[0]:
                yield start, backer[: interval[0] - start], owner
            if end > interval[1]:
                yield interval[1], backer[interval[1] - start :], owner

    def _assert_read_access(self, addr: int, size: int) -> None:
        self._assert_unencrypted_access(addr, size)
        super()._assert_read_access(addr, size)

    def _backers_with_owners_for_writing(
        self, addr: int, size: int
    ) -> Iterator[tuple[int, bytearray | memoryview | mmap | list[int], Clemory]]:
        self._assert_unencrypted_access(addr, size)
        yield from super()._backers_with_owners_for_writing(addr, size)

    def _backers_for_reading(self, addr=0) -> Iterator[tuple[int, bytes | bytearray | memoryview | mmap | list[int]]]:
        for start, backer, _ in self._backers_with_owners_for_reading(addr):
            yield start, backer

    def _assert_unencrypted_access(self, addr, size):
        """
        Make sure that the access does not cover encrypted memory regions
        If it does, raise an error

        Cases:
        - Access starts before encrypted region and ends after it
        - Access starts within encrypted region
        - Access ends within encrypted region

        :param addr:
        :param size:
        :return:
        """
        interval = self._effective_crypt_interval()
        if interval is None:
            return

        if size > 0 and addr < interval[1] and addr + size > interval[0]:
            raise EncryptedDataAccessException("Accessing encrypted memory region", addr)


class EncryptedDataAccessException(Exception):
    """
    Special exception to be raised when access to encrypted memory is attempted
    """

    def __init__(self, message, addr):
        super().__init__(message)
        self.addr = addr
