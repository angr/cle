from elftools.dwarf.die import DIE


class VariableType:
    """
    DW_TAG_base_type for DWARF
    """

    def __init__(self, name: str, byte_size: int):
        self.name = name
        self.byte_size = byte_size

    @staticmethod
    def read_from_die(die: DIE):
        return VariableType(
            name=die.attributes["DW_AT_name"].value.decode(),
            byte_size=die.attributes["DW_AT_byte_size"].value,
        )


class ClassType:
    types = {
        "int": "Integer",
        "long int": "Integer",
        "long unsigned int": "Integer",
        "__int128": "Integer",
        "bool": "Boolean",
        "char": "Integral",
        "float": "Float",
        "double": "Float",
        "long double": "Float",
    }

    @classmethod
    def get(cls, typename):
        """
        Given a class name, return the type
        """
        if typename not in cls.types:
            print("classtype")
            print(typename)
            import IPython

            IPython.embed()
        name = cls.types[typename]

        # Prefix with complex
        if "complex" in typename.lower():
            return "Complex%s" % name
        return name
