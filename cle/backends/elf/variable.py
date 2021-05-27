from typing import Optional, Any
from .variable_type import VariableType


class Variable:
    def __init__(self, name: Optional[str], type_: Optional[VariableType], decl_file: Optional[str], decl_line: Optional[int],
                 addr: Optional[int]=None, sort: str = ""):
        self.name = name
        self.type = type_
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.addr = addr
        # sort = 'stack' | 'register' | 'global'
        self.sort = sort
