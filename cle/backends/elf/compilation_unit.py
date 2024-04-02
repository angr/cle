import os.path
from typing import Dict, Generator, List, Tuple

from cle.address_translator import AT

from .subprogram import Subprogram
from .variable import Variable


class CompilationUnit:
    """
    CompilationUnit for DWARF
    See http://dwarfstd.org/doc/DWARF5.pdf page 60
    """

    def __init__(self, name, comp_dir, language, ranges: List[Tuple[int, int]], elf_object):
        self.name = name
        self.comp_dir = comp_dir
        self.file_path = os.path.join(self.comp_dir, self.name)
        self.language = language
        self.functions: Dict[int, Subprogram] = {}
        self.global_variables: List[Variable] = []
        self._elf_object = elf_object

        self._ranges = ranges
        self.low_pc = min(ranges)[0]
        self.high_pc = max(ranges)[0]

    def __repr__(self):
        return f"<CompilationUnit {self.name}@{self.file_path}>"

    @property
    def min_addr(self):
        return AT.from_rva(self.low_pc, self._elf_object).to_mva()

    @property
    def max_addr(self):
        return AT.from_rva(self.high_pc, self._elf_object).to_mva()

    @property
    def ranges(self) -> Generator[int, None, None]:
        for lo, hi in self._ranges:
            yield AT.from_rva(lo, self._elf_object).to_mva(), AT.from_rva(hi, self._elf_object).to_mva()

    @property
    def multiple_ranges(self) -> bool:
        return len(self._ranges) > 1
