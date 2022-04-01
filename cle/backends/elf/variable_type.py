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
        dw_at_name = die.attributes.get("DW_AT_name", None)
        byte_size = die.attributes.get("DW_AT_byte_size", None)
        if byte_size is None:
            return None
        return VariableType(
            name = dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size = byte_size.value
        )
