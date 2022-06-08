from elftools.dwarf.die import DIE


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
