from .abs_obj import Symbol

class ELFSymbol(Symbol):
    def __init__(self, name, addr, size, binding, sym_type, sh_info):
        super(Symbol, self).__init__()
        self.name = name
        self.addr = addr
        self.size = size
        self.binding = binding
        self.type = sym_type
        self.sh_info = sh_info
