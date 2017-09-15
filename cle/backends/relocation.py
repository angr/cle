from __future__ import print_function
import logging
from ..address_translator import AT

l = logging.getLogger('cle.backends.relocation')

class Relocation(object):
    """
    A representation of a relocation in a binary file. Smart enough to
    relocate itself.

    :ivar owner_obj:    The binary this relocation was originaly found in, as a cle object
    :ivar symbol:       The Symbol object this relocation refers to
    :ivar relative_addr:    The address in owner_obj this relocation would like to write to
    :ivar rebased_addr: The address in the global memory space this relocation would like to write to
    :ivar resolvedby:   If the symbol this relocation refers to is an import symbol and that import has been resolved,
                        this attribute holds the symbol from a different binary that was used to resolve the import.
    :ivar resolved:     Whether the application of this relocation was succesful
    """
    def __init__(self, owner, symbol, relative_addr):
        super(Relocation, self).__init__()
        self.owner_obj = owner
        self.arch = owner.arch
        self.symbol = symbol
        self.relative_addr = relative_addr
        self.resolvedby = None
        self.resolved = False
        self.resolvewith = None
        if self.symbol is not None and self.symbol.is_import:
            self.owner_obj.imports[self.symbol.name] = self

    def resolve_symbol(self, solist, bypass_compatibility=False): # pylint: disable=unused-argument
        if self.symbol.is_static:
            # A static symbol should only be resolved by itself.
            self.resolve(self.symbol)
            return True

        weak_result = None
        for so in solist:
            symbol = so.get_symbol(self.symbol.name)
            if symbol is not None and symbol.is_export:
                if not symbol.is_weak:
                    self.resolve(symbol)
                    return True
                elif weak_result is None:
                    weak_result = symbol
            # TODO: Was this check obsolted by the addition of is_static?
            # I think right now symbol.is_import = !symbol.is_export
            elif symbol is not None and not symbol.is_import and so is self.owner_obj:
                if not symbol.is_weak:
                    self.resolve(symbol)
                    return True
                elif weak_result is None:
                    weak_result = symbol

        if weak_result is not None:
            self.resolve(weak_result)
            return True

        if self.symbol.is_weak:
            return False

        new_symbol = self.owner_obj.loader.extern_object.make_extern(self.symbol.name)
        self.resolve(new_symbol)
        return True

    def resolve(self, obj):
        self.resolvedby = obj
        self.resolved = True
        if self.symbol is not None:
            if obj is not None:
                l.debug('%s from %s resolved by %s from %s at %#x', self.symbol.name, self.owner_obj.provides, obj.name, obj.owner_obj.provides, obj.rebased_addr)
            self.symbol.resolve(obj)

    @property
    def rebased_addr(self):
        return AT.from_rva(self.relative_addr, self.owner_obj).to_mva()

    @property
    def linked_addr(self):
        return AT.from_rva(self.relative_addr, self.owner_obj).to_lva()

    warned_addr = False

    @property
    def addr(self):
        if not Relocation.warned_addr:
            print("\x1b[31;1mDeprecation warning: Relocation.addr is ambiguous, please use relative_addr, linked_addr, or rebased_addr\x1b[0m")
            Relocation.warned_addr = True
        return self.linked_addr

    @property
    def dest_addr(self):
        return self.relative_addr

    @property
    def value(self):    # pylint: disable=no-self-use
        l.error('Value property of Relocation must be overridden by subclass!')
        return 0

    def relocate(self, solist, bypass_compatibility=False):
        """
        Applies this relocation. Will make changes to the memory object of the
        object it came from.

        This implementation is a generic version that can be overridden in subclasses.

        :param solist:       A list of objects from which to resolve symbols.
        """
        if not self.resolve_symbol(solist, bypass_compatibility):
            return False

        self.owner_obj.memory.write_addr_at(self.dest_addr, self.value)
