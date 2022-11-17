import os.path

from typing import Dict, List
from .variable import Variable
from .subprogram import Subprogram


class CompilationUnit:
    """
    CompilationUnit for DWARF
    See http://dwarfstd.org/doc/DWARF5.pdf page 60
    """

    def __init__(self, name, comp_dir, low_pc, high_pc, language):
        self.name = name
        self.comp_dir = comp_dir
        self.file_path = os.path.join(self.comp_dir, self.name)
        self.low_pc = low_pc
        self.high_pc = high_pc
        self.language = language
        self.functions: Dict[int, Subprogram] = {}
        self.global_variables: List[Variable] = []

    @property
    def global_vars(self):
        '''
        an alternative property to self.global_variables that resolve
        variable name (str) -> Variable (Variable type)
        '''
        global_vars = {}
        for global_var in self.global_variables:
            global_vars[global_var.name] = global_var
        return global_vars
