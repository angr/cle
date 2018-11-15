import struct

from . import SimData
from ...relocation import Relocation


class StaticData(SimData):
    """
    A simple SimData utility class to use when you have a SimData which should provide just a static
    set of bytes. To use, implement the following:

    :cvar name:     The name of the symbol to provide.
    :cvar libname:  The name of the library from which the symbol originally comes (currently unused).
    :cvar data:     The bytes to provide
    """
    type = SimData.TYPE_OBJECT
    data = NotImplemented  # type: bytes

    @classmethod
    def static_size(cls, owner):
        return len(cls.data)

    def value(self):
        return self.data


class StaticWord(SimData):
    """
    A simple SimData utility class to use when you have a SimData which should provide just a static
    integer. To use, implement the following:

    :cvar name:     The name of the symbol to provide.
    :cvar libname:  The name of the library from which the symbol originally comes (currently unused).
    :cvar word:     The value to provide
    :cvar wordsize: (optional) The size of the value in bytes, default the CPU wordsize
    """
    type = SimData.TYPE_OBJECT
    word = NotImplemented  # type: int
    wordsize = None # type: int

    @classmethod
    def static_size(cls, owner):
        return owner.arch.bytes if cls.wordsize is None else cls.wordsize

    def value(self):
        return struct.pack(self.owner.arch.struct_fmt(size=self.wordsize), self.word)


class PointTo(SimData):
    """
    A simple SimData utility class to use when you have a SimData which should provide just a
    pointer to some other symbol. To use, implement the following:

    :cvar name:         The name of the symbol to provide.
    :cvar libname:      The name of the library from which the symbol originally comes (currently unused).
    :cvar pointto_name: The name of the symbol to point to
    :cvar pointto_type: The type of the symbol to point to (usually ``Symbol.TYPE_FUNCTION`` or
                        ``Symbol.TYPE_OBJECT``)
    :cvar addend:       (optional) an integer to be added to the symbol's address before storage
    """
    pointto_name = NotImplemented  # type: str
    pointto_type = NotImplemented  # type: int
    type = SimData.TYPE_OBJECT
    addend = 0  # type: int

    @classmethod
    def static_size(cls, owner):
        return owner.arch.bytes

    def value(self):
        return bytes(self.size)

    def relocations(self):
        return [SimDataSimpleRelocation(
            self.owner,
            self.owner.make_import(self.pointto_name, self.pointto_type),
            self.relative_addr,
            self.addend
        )]


class SimDataSimpleRelocation(Relocation):
    """
    A relocation used to implement PointTo. Pretty simple.
    """
    def __init__(self, owner, symbol, addr, addend):
        super(SimDataSimpleRelocation, self).__init__(owner, symbol, addr)
        self.addend = addend

    @property
    def value(self):
        return self.resolvedby.rebased_addr + self.addend
