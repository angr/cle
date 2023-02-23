from enum import Enum
from typing import Optional, List, Tuple, Any, TYPE_CHECKING

from elftools.dwarf.die import DIE

from cle.address_translator import AT

from .variable_type import VariableType

if TYPE_CHECKING:
    from .elf import ELF
    from .subprogram import LexicalBlock

DW_OP_reg0 = 0x50


class VariableLocationType(Enum):
    """
    Describes the various types of variable locations.
    """

    Register = 0
    Stack = 1
    Global = 2


class VariableLocation:
    """
    Describes a variable location (register, on stack, or in the global memory region).
    """

    __slots__ = (
        "loc_type",
        "relative_addr",
    )

    def __init__(self, loc_type: VariableLocationType, relative_addr):
        self.loc_type = loc_type
        self.relative_addr = relative_addr

    def __repr__(self):
        if self.loc_type == VariableLocationType.Register:
            return f"{self.loc_type.name}:{self.relative_addr}"
        return f"{self.loc_type.name}:{self.relative_addr:#x}"


class Variable:
    """
    Variable for DWARF
    from a DW_TAG_variable or DW_TAG_formal_parameter

    :ivar str name:         The name of the variable
    :ivar relative_addr:    The relative addr (base addr depends on the type)
    :ivar lexical_block:    For a local variable, the lexical block where the variable is declared
    """

    __slots__ = (
        "_elf_object",
        "relative_addr",
        "name",
        "_type_offset",
        "decl_line",
        "decl_file",
        "lexical_block",
        "external",
        "declaration_only",
        "location",
    )

    def __init__(self, elf_object: "ELF"):
        self._elf_object = elf_object
        # all other optional params can be set afterwards
        self.relative_addr = None
        self.name = None
        self._type_offset = None
        self.decl_line = None
        self.decl_file = None
        self.lexical_block = None
        self.external = False
        self.declaration_only = False
        self.location: Optional[List[Tuple[int, int, Optional[VariableLocation]]]] = None

    @staticmethod
    def from_die(die: DIE, expr_parser, elf_object: "ELF", dwarf, lexical_block: Optional["LexicalBlock"] = None):
        # first the address
        var = None
        if "DW_AT_location" in die.attributes:
            loc_attr = die.attributes["DW_AT_location"]
            if loc_attr.form == "DW_FORM_exprloc":
                parsed_exprs = expr_parser.parse_expr(loc_attr.value)
                if len(parsed_exprs) == 1 and parsed_exprs[0].op_name == "DW_OP_addr":
                    addr = parsed_exprs[0].args[0]
                    var = MemoryVariable(elf_object, addr)
                elif len(parsed_exprs) == 1 and parsed_exprs[0].op_name == "DW_OP_fbreg":
                    addr = parsed_exprs[0].args[0]
                    var = StackVariable(elf_object, addr)
                elif len(parsed_exprs) == 1 and parsed_exprs[0].op_name.startswith("DW_OP_reg"):
                    addr = parsed_exprs[0].op - DW_OP_reg0
                    var = RegisterVariable(elf_object, addr)
                else:
                    # we do not support the location form (yet)
                    var = Variable(elf_object)
            elif loc_attr.form == "DW_FORM_sec_offset":
                var = Variable(elf_object)
                loc_lists = dwarf.location_lists()
                var.location = Variable.load_variable_location(loc_lists, loc_attr.value, expr_parser)

        if var is None:
            var = Variable(elf_object)

        if "DW_AT_name" in die.attributes:
            var.name = die.attributes["DW_AT_name"].value.decode("utf-8")
        if "DW_AT_type" in die.attributes:
            var._type_offset = die.attributes["DW_AT_type"].value + die.cu.cu_offset
        if "DW_AT_decl_line" in die.attributes:
            var.decl_line = die.attributes["DW_AT_decl_line"].value
        if "DW_AT_external" in die.attributes:
            var.external = True
        if "DW_AT_declaration" in die.attributes:
            var.declaration_only = True

        var.lexical_block = lexical_block

        return var

    @staticmethod
    def load_variable_location(
        location_lists, offset: int, expr_parser
    ) -> List[Tuple[int, int, Optional[VariableLocation]]]:
        loc_list = location_lists.get_location_list_at_offset(offset)
        locs = []
        for entry in loc_list:
            parsed_exprs = expr_parser.parse_expr(entry.loc_expr)
            loc_expr = None
            if len(parsed_exprs) == 1:
                the_parsed_expr = parsed_exprs[0]
                if the_parsed_expr.op_name == "DW_OP_addr":
                    loc_expr = VariableLocation(VariableLocationType.Global, the_parsed_expr.args[0])
                elif the_parsed_expr.op_name == "DW_OP_fbreg":
                    loc_expr = VariableLocation(VariableLocationType.Stack, the_parsed_expr.args[0])
                elif the_parsed_expr.op_name.startswith("DW_OP_reg"):
                    loc_expr = VariableLocation(VariableLocationType.Register, the_parsed_expr.op - DW_OP_reg0)
            locs.append((entry.begin_offset, entry.end_offset, loc_expr))
        return locs

    # overwritten for stack variables
    def rebased_addr_from_cfa(self, cfa: int):
        """
        The address of this variable in the global memory.

        :param cfa:     The canonical frame address as described by the DWARF standard.
        """
        return self.rebased_addr

    @property
    def rebased_addr(self):
        return None

    @property
    def addr(self):
        """
        Please use 'relative_addr' or 'rebased_addr' instead.
        """
        return self.relative_addr

    @property
    def type(self) -> VariableType:
        try:
            return self._elf_object.type_list[self._type_offset]
        except KeyError:
            return None

    @property
    def sort(self) -> str:
        # sort = 'stack' | 'register' | 'global'
        return "unknown"


class MemoryVariable(Variable):
    """
    This includes all variables that are not on the stack and not in a register.
    So all global variables, and also local static variables in C!
    """

    __slots__ = ()

    def __init__(self, elf_object: "ELF", relative_addr):
        super().__init__(elf_object)
        self.relative_addr = relative_addr

    @property
    def rebased_addr(self):
        return AT.from_rva(self.relative_addr, self._elf_object).to_mva()

    @property
    def sort(self) -> str:
        return "global"


class StackVariable(Variable):
    """
    Stack Variable from DWARF.
    """

    __slots__ = ()

    def __init__(self, elf_object: "ELF", relative_addr):
        super().__init__(elf_object)
        self.relative_addr = relative_addr

    def rebased_addr_from_cfa(self, cfa: int):
        return self.relative_addr + cfa

    @property
    def sort(self) -> str:
        return "stack"


class RegisterVariable(Variable):
    """
    Register Variable from DWARF.
    """

    __slots__ = ()

    def __init__(self, elf_object: "ELF", register_addr):
        super().__init__(elf_object)
        # FIXME should this really go into relative addr?
        self.relative_addr = register_addr

    @property
    def sort(self) -> str:
        return "register"
