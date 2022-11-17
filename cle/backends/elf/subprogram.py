from typing import List
from .variable import Variable


class LexicalBlock:
    """
    A lexical block is a sequence of source statements, e.g. a while/for
    loop or an if statement or some bracketed block.

    Corresponds to a DW_TAG_LexicalBlock in DWARF.

    :param super_block: The lexical block which contains this block
    :param low_pc:      The relative start address of the block
    :param high_pc:     The relative end address of the block

    :ivar super_block:  The block which contains this block
    :type super_block:  Lexical_block
    :ivar subprogram:   The Subprogram which contains this block
    :type subprogram:   Subprogram
    :ivar low_pc:       The relative start address of the subprogram
    :ivar high_pc:      The relative end address of the subprogram
    """

    def __init__(self, super_block: 'LexicalBlock', low_pc, high_pc) -> None:
        self.super_block = super_block
        self.subprogram = super_block.subprogram
        self.low_pc = low_pc
        self.high_pc = high_pc
        self.lexical_blocks: List[LexicalBlock] = []
        self.local_vars = {}

    def add_variable(self, var: Variable) -> None:
        """
        Adds a variable to this block and propagates it to the subprogram.local_variables
        """
        self.local_vars[var.name] = var
        self.subprogram.local_variables.append(var)

    # depth-first
    def __iter__(self):
        yield self
        for child in self.lexical_blocks:
            for node in child:
                yield node


class Subprogram(LexicalBlock):
    """
    DW_TAG_subprogram for DWARF. The behavior is mostly inherited from
    LexicalBlock to avoid redundancy.

    :param name:     The name of the function/program
    :param low_pc:   The relative start address of the subprogram
    :param high_pc:  The relative end address of the subprogram

    :ivar name:            The name of the function/program
    :type name:            str
    :ivar local_variables: All local variables in a Subprogram (they may reside in serveral child blocks)
    :type local_variables: List[Variables]
    """

    def __init__(self, name, low_pc, high_pc) -> None:
        # pass self as the super_block of this subprogram
        self.subprogram = self
        super().__init__(self, low_pc, high_pc)
        self.name = name
        self.local_variables = []
