from elftools.dwarf.descriptions import ExprDumper
from elftools.dwarf.descriptions import describe_reg_name

# Keep a cache of dumpers with lookup based on the struct
_DWARF_EXPR_DUMPER_CACHE = {}

def get_dwarf_from_expr(expr, structs, cu_offset=None):
    """
    Given an expression, 
    """
    cache_key = id(structs)
    if cache_key not in _DWARF_EXPR_DUMPER_CACHE:
        _DWARF_EXPR_DUMPER_CACHE[cache_key] = RegisterDumper(structs)
    dwarf_expr_dumper = _DWARF_EXPR_DUMPER_CACHE[cache_key]
    return dwarf_expr_dumper.dump_register(expr, cu_offset)

def get_register_from_expr(expr, structs, cu_offset=None):
    """
    A tweaked https://github.com/eliben/pyelftools/blob/master/elftools/dwarf/descriptions.py#L135
    to allow parsing the expression to just get the register.
    """
    cache_key = id(structs)
    if cache_key not in _DWARF_EXPR_DUMPER_CACHE:
        _DWARF_EXPR_DUMPER_CACHE[cache_key] = RegisterDumper(structs)
    dwarf_expr_dumper = _DWARF_EXPR_DUMPER_CACHE[cache_key]
    return dwarf_expr_dumper.dump_register(expr, cu_offset)

class RegisterDumper(ExprDumper):
    """A dumper to get registers from an expression.
    """
    def dump_register(self, expr, cu_offset=None):
        """
        Parse a DWARF expression (list of integer values) into the register.
        """
        parsed = self.expr_parser.parse_expr(expr)
        registers = []
        for deo in parsed:
            registers.append(self._dump_to_string(deo.op, deo.op_name, deo.args, cu_offset))
        return registers
