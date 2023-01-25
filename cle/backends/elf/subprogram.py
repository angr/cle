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

    :ivar low_pc:       The relative start address of the subprogram
    :ivar high_pc:      The relative end address of the subprogram
    :ivar child_blocks: Lexical blocks inside this block (only direct childs)
    :type child_blocks: List[LexicalBlock]
    """

    def __init__(self, low_pc, high_pc) -> None:
        self.low_pc = low_pc
        self.high_pc = high_pc
        self.child_blocks: List[LexicalBlock] = []


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
        super().__init__(low_pc, high_pc)
        self.name = name
        self.local_variables: List[Variable] = []
