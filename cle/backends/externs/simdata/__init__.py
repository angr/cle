from collections import defaultdict
from typing import List

from ...relocation import Relocation
from ...symbol import Symbol

# pylint: disable=unused-argument,no-self-use

class SimData(Symbol):
    name = NotImplemented  # type: str
    type = NotImplemented  # type: int
    libname = NotImplemented  # type: str

    @staticmethod
    def static_size(arch) -> int:
        return NotImplemented

    def value(self) -> bytes:
        return NotImplemented

    def relocations(self) -> List[Relocation]:
        return []


registered_data = defaultdict(list)

def register(simdata_cls):
    if simdata_cls.name is None:
        return
    registered_data[simdata_cls.name].append(simdata_cls)

def lookup(name, libname):
    weak_option = None
    for simdata_cls in registered_data[name]:
        if simdata_cls.libname == libname:
            return simdata_cls
        elif simdata_cls is None or libname is None:
            weak_option = simdata_cls

    return weak_option

# pylint: disable=unused-import
from . import io_file
from . import progname
