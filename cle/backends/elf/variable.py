from typing import Optional, Any


class Variable:
    def __init__(self, name: Optional[str], type_: Optional[Any], decl_file: Optional[str], decl_line: Optional[int],
                 addr: Optional[int]=None):
        self.name = name
        self.type = type_
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.addr = addr
