from typing import Optional, TYPE_CHECKING
from .variable_type import VariableType
if TYPE_CHECKING:
    from .elf import ELF


class Variable:
    """
    Variable for DWARF
    from a DW_TAG_variable or DW_TAG_formal_parameter
    """
    def __init__(self, elf_object: 'ELF', name: Optional[str], type_: Optional[VariableType],
                 decl_file: Optional[str], decl_line: Optional[int],
                 addr: Optional[int]=None, sort: str = ""):
        self.name = name
        self.type = type_
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.addr = addr
        # sort = 'stack' | 'register' | 'global'
        self.sort = sort
        self._elf_object = elf_object

    def addr_from_state(self, state):
        if self.sort == 'stack':
            cfa = state.dwarf_cfa
            return cfa + self.addr
        elif self.sort == 'global':
            mapped_base = self._elf_object.mapped_base
            return mapped_base + self.addr
        return None
