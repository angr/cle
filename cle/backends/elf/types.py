from elftools.dwarf.die import DIE


class ClassType:
    types = {
        "int": "Integer",
        "long int": "Integer",
        "unsigned int": "Integer",
        "signed char": "Integral",
        "short unsigned int": "Integer",
        "long long int": "Integer",
        "long long unsigned int": "Integer",
        "long unsigned int": "Integer",
        "wchar_t": "Integral",
        # the type size_t is defined as unsigned long
        "size_t": "Integer",
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
