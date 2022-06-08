from collections import defaultdict
from typing import List, Type, Optional

from ...relocation import Relocation
from ...symbol import Symbol, SymbolType

# pylint: disable=unused-argument,no-self-use

class SimData(Symbol):
    """
    A SimData class is used to provide data when there is an unresolved data import symbol.

    To use it, subclass this class and implement the below attributes and methods.

    :cvar name:     The name of the symbol to provide
    :cvar libname:  The name of the library from which the symbol originally comes (currently unused).
    :cvar type:     The type of the symbol, usually ``SymbolType.TYPE_OBJECT``.

    Use the below `register` method to register SimData subclasses with CLE.

    NOTE: SimData.type hides the Symbol.type instance property
    """
    name = NotImplemented  # type: str
    type = NotImplemented  # type: SymbolType
    libname = NotImplemented  # type: str

    @classmethod
    def static_size(cls, owner) -> int:
        """
        Implement me: return the size of the symbol in bytes before it gets constructed

        :param owner:   The ExternObject owning the symbol-to-be. Useful to get at ``owner.arch``.
        """
        return NotImplemented

    def value(self) -> bytes:
        """
        Implement me: the initial value of the bytes in memory for the symbol. Should return a
        bytestring of the same length as static_size returned. (owner is ``self.owner`` now)
        """
        return NotImplemented

    def relocations(self) -> List[Relocation]:
        """
        Maybe implement me: If you like, return a list of relocation objects to apply. To create
        new import symbols, use ``self.owner.make_extern_import``.
        """
        return []


registered_data = defaultdict(list)


def register(simdata_cls: Type[SimData]):
    """
    Register the given SimData class with CLE so it may be used during loading
    """
    if simdata_cls.name is None:
        return
    registered_data[simdata_cls.name].append(simdata_cls)


def lookup(name: str, libname) -> Optional[Type[SimData]]:
    weak_option = None
    for simdata_cls in registered_data[name]:
        if type(libname) is type(simdata_cls.libname) is str and simdata_cls.libname.startswith(libname):
            return simdata_cls
        elif simdata_cls is None or libname is None:
            weak_option = simdata_cls

    return weak_option

# pylint: disable=unused-import
from . import io_file
from . import glibc_startup
