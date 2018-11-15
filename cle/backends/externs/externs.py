import logging

from cle.backends import Backend, Symbol, Segment
from cle.utils import ALIGN_UP
from cle.errors import CLEOperationError
from cle.address_translator import AT

l = logging.getLogger(name=__name__)

class ExternSegment(Segment):
    is_readable = True
    is_writable = True
    is_executable = True


class ExternObject(Backend):
    def __init__(self, loader, map_size=0x8000):
        super(ExternObject, self).__init__('cle##externs', loader=loader)
        self.next_addr = 0
        self.map_size = map_size
        self.set_arch(loader.main_object.arch)
        self.memory.add_backer(0, bytes(map_size))
        self.provides = 'extern-address space'
        self.pic = True

        self.segments.append(ExternSegment('externs', 0, 0, self.map_size))


    def make_extern(self, name, size=1, alignment=8, thumb=False, sym_type=Symbol.TYPE_FUNCTION, libname=None):
        try:
            return self._symbol_cache[name]
        except KeyError:
            pass

        l.info("Creating extern symbol for %s", name)

        SymbolCls = Symbol
        simdata = lookup(name, libname)
        if simdata is not None:
            SymbolCls = simdata
            size = simdata.static_size(self.arch)
            if sym_type != simdata.type:
                l.warning("Symbol type mismatch between export request and response for %s. What's going on?", name)

        addr = self.allocate(size, alignment=alignment, thumb=thumb)

        if hasattr(self.loader.main_object, 'is_ppc64_abiv1') and self.loader.main_object.is_ppc64_abiv1 and sym_type == Symbol.TYPE_FUNCTION:
            func_symbol = SymbolCls(self, name + '#func', AT.from_mva(addr, self).to_rva(), size, sym_type)
            func_symbol.is_export = True
            func_symbol.is_extern = True
            self._symbol_cache[name + '#func'] = func_symbol
            self.symbols.add(func_symbol)
            self._init_symbol(func_symbol)

            toc = self.allocate(0x18, alignment=8)
            self.memory.pack_word(AT.from_mva(toc, self).to_rva(), addr)
            addr = toc
            sym_type = Symbol.TYPE_OBJECT
            SymbolCls = Symbol

        new_symbol = SymbolCls(self, name, AT.from_mva(addr, self).to_rva(), size, sym_type)
        new_symbol.is_export = True
        new_symbol.is_extern = True

        self._symbol_cache[name] = new_symbol
        self.symbols.add(new_symbol)
        self._init_symbol(new_symbol)
        return new_symbol

    def get_pseudo_addr(self, name):
        return self.make_extern(name).rebased_addr

    def allocate(self, size=1, alignment=8, thumb=False):
        addr = ALIGN_UP(self.next_addr, alignment) | thumb
        self.next_addr = addr + size
        if self.next_addr > self.map_size:
            raise CLEOperationError("Ran out of room in the extern object...! Report this as a bug.")
        return addr + self.mapped_base

    @property
    def max_addr(self):
        return AT.from_rva(self.map_size, self).to_mva()

    def make_import(self, name, sym_type):
        if name not in self.imports:
            sym = Symbol(self, name, 0, 0, sym_type)
            sym.is_import = True
            sym.is_extern = True
            self.imports[name] = sym
            return sym
        else:
            sym = self.imports[name]
            if sym.type != sym_type:
                raise CLEOperationError("Created the same extern import %s with two different types. Something isn't right!")
            return sym

    def _init_symbol(self, symbol):
        if isinstance(symbol, SimData):
            self.memory.store(symbol.relative_addr, symbol.value())
            # the unfortunate fact of the matter is that if we are being polled for a relocation we need its contents to
            # be resolved, like, yesterday. so recurse here, lord help us.
            # if we want extern relocations to be able to depend on other objects we are in for a serious refactor
            # perhaps split resolution and relocation into two different phases?
            relocs = symbol.relocations()
            self.relocs.extend(relocs)
            for reloc in relocs:
                reloc.relocate([self])


class KernelObject(Backend):
    def __init__(self, loader, map_size=0x8000):
        super(KernelObject, self).__init__('cle##kernel', loader=loader)
        self.map_size = map_size
        self.set_arch(loader.main_object.arch)
        self.memory.add_backer(0, bytes(map_size))
        self.provides = 'kernel space'
        self.pic = True

    def add_name(self, name, addr):
        self._symbol_cache[name] = Symbol(self, name, AT.from_mva(addr, self).to_rva(), 1, Symbol.TYPE_FUNCTION)

    @property
    def max_addr(self):
        return AT.from_rva(self.map_size, self).to_mva()

from .simdata import lookup, SimData
