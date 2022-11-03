from typing import Optional
from .variable_type import VariableType


class Variable:
    """
    Variable for DWARF
    from a DW_TAG_variable or DW_TAG_formal_parameter
    """
    def __init__(self, name: Optional[str], type_: Optional[VariableType], decl_file: Optional[str], decl_line: Optional[int],
                 addr: Optional[int]=None, sort: str = ""):
        self.name = name
        self.type = type_
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.addr = addr
        # sort = 'stack' | 'register' | 'global'
        self.sort = sort

    def addr_from_state(self, state):
        cfa = state.dwarf_cfa
        if sort == 'stack':
            return cfa + self.addr
        return None
