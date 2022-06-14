from elftools.dwarf.die import DIE


class ClassType:
    types = {
        "int": "Integer",
        "long int": "Integer",
        "unsigned int": "Integer",
        "unsigned char": "Integral",
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
        "_Bool": "Boolean",
        "char": "Integral",
        "float": "Float",
        "double": "Float",
        "long double": "Float",
    }

    patterns = {
        "int": "Integer",
        "char": "Integral",
        "float": "Float",
        "double": "Float",
    }

    @classmethod
    def get(cls, typename):
        """
        Given a class name, return the type
        """
        classname = None
        for pattern in cls.patterns:
            if pattern in typename:
                classname = cls.patterns[pattern]
                break

        if not classname:
            if typename not in cls.types:
                print("classtype")
                print(typename)
                import IPython

                IPython.embed()
            classname = cls.types[typename]

        # Prefix with complex
        if "complex" in typename.lower():
            return "Complex%s" % classname
        return classname
