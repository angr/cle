
class Variable:
    def __init__(self, name, type_, decl_file, decl_line, addr=None):
        self.name = name
        self.type = type_
        self.decl_file = decl_file
        self.decl_line = decl_line
        self.addr = None
