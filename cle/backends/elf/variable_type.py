from elftools.dwarf.die import DIE


class VariableType:
    """
    DW_TAG_base_type for DWARF
    """
    def __init__(self, name: str, byte_size:int):
        self.name = name
        self.byte_size = byte_size

    @staticmethod
    def read_from_die(die: DIE):
        return VariableType(
            name = die.attributes["DW_AT_name"].value.decode(),
            byte_size = die.attributes["DW_AT_byte_size"].value
        )
