from elftools.dwarf.die import DIE


class ClassType:
    types = {
        "int": "Integer",
        "short": "Integer",
        "long int": "Integer",
        "unsigned int": "Integer",
        "unsigned char": "Integer",
        "signed char": "Integer",
        "short unsigned int": "Integer",
        "long long int": "Integer",
        "long long unsigned int": "Integer",
        "long unsigned int": "Integer",
        "wchar_t": "Integer",
        # the type size_t is defined as unsigned long
        "size_t": "Integer",
        "__int128": "Integer",
        "bool": "Integer",
        "_Bool": "Integer",
        "char": "Integer",
        "float": "Float",
        "double": "Float",
        "long double": "Float",
    }

    patterns = {
        "int": "Integer",
        "char": "Integer",
        "float": "Float",
        "double": "Float",
        "short": "Integer",
        # These are fortran types - skipping for now. Also see parse_string_type
        # TODO https://docs.oracle.com/cd/E19957-01/805-4939/6j4m0vn6m/index.html
        "logical": "Unknown",
        "complex(kind=": "Unknown",
        "real(kind=": "Unknown",
        # C99
        "__ARRAY_SIZE_TYPE__": "Unknown",
        # Boost
        "param_type": "Unknown",
        # No idea
        "sizetype": "Unknown",
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

        # __unknown__
        if "unknown" in typename:
            return "Unknown"

        if not classname:
            if typename not in cls.types:
                # This should be an interactive IPython
                return "Unknown"
            classname = cls.types[typename]

        # Prefix with complex
        if "complex" in typename.lower():
            return "Complex%s" % classname
        return classname
