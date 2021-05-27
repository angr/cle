from typing import List
from .variable import Variable


class Subprogram:
    """
    DW_TAG_subprogram for DWARF
    """
    local_variables: List[Variable] = []

    def __init__(self, name, low_pc, high_pc,) -> None:
        self.name = name
        self.low_pc = low_pc
        self.high_pc = high_pc
