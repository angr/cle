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

    @property
    def local_vars(self):
        '''
        an alternative property for attribute local_variable that resolve
        variable name -> Variable (Variable type)
        '''
        local_vars = {}
        for local_var in self.local_variables:
            local_vars[local_var.name] = local_var
        return local_vars
