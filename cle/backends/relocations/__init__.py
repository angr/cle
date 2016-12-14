import archinfo

import os
import importlib
from collections import defaultdict

import logging
l = logging.getLogger('cle.relocations')

ALL_RELOCATIONS = defaultdict(dict)
complaint_log = set()
path = os.path.dirname(os.path.abspath(__file__))


def load_relocations():
    for filename in os.listdir(path):
        if not filename.endswith('.py'):
            continue
        if filename == '__init__.py':
            continue

        module = importlib.import_module('.%s' % filename[:-3], 'cle.backends.relocations')

        try:
            arch_name = module.arch
        except AttributeError:
            continue

        for item_name in dir(module):
            if item_name not in archinfo.defines:
                continue
            item = getattr(module, item_name)
            if not isinstance(item, type) or not issubclass(item, Relocation):
                continue

            ALL_RELOCATIONS[arch_name][archinfo.defines[item_name]] = item


def get_relocation(arch, r_type):
    if r_type == 0:
        return None
    try:
        return ALL_RELOCATIONS[arch][r_type]
    except KeyError:
        if (arch, r_type) not in complaint_log:
            complaint_log.add((arch, r_type))
            l.warning("Unknown reloc %d on %s", r_type, arch)
        return None


class Relocation(object):
    """
    A representation of a relocation in a binary file. Smart enough to
    relocate itself.

    :ivar owner_obj:    The binary this relocation was originaly found in, as a cle object
    :ivar symbol:       The Symbol object this relocation refers to
    :ivar addr:         The address in owner_obj this relocation would like to write to
    :ivar rebased_addr: The address in the global memory space this relocation would like to write to
    :ivar resolvedby:   If the symbol this relocation refers to is an import symbol and that import has been resolved,
                        this attribute holds the symbol from a different binary that was used to resolve the import.
    :ivar resolved:     Whether the application of this relocation was succesful
    """
    def __init__(self, owner, symbol, addr, addend=None):
        super(Relocation, self).__init__()
        self.owner_obj = owner
        self.arch = owner.arch
        self.symbol = symbol
        self.addr = addr
        self.is_rela = addend is not None
        self._addend = addend
        self.resolvedby = None
        self.resolved = False
        if self.symbol is not None and self.symbol.is_import:
            self.owner_obj.imports[self.symbol.name] = self

    @property
    def addend(self):
        if self.is_rela:
            return self._addend
        else:
            return self.owner_obj.memory.read_addr_at(self.addr, orig=True)

    def resolve_symbol(self, solist, bypass_compatibility=False):
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

        return False

    def resolve(self, obj):
        self.resolvedby = obj
        self.resolved = True
        if self.symbol is not None:
            if obj is not None:
                l.debug('%s from %s resolved by %s from %s at %#x', self.symbol.name, self.owner_obj.provides, obj.name, obj.owner_obj.provides, obj.rebased_addr)
            self.symbol.resolve(obj)

    @property
    def rebased_addr(self):
        return self.addr + self.owner_obj.rebase_addr

    @property
    def dest_addr(self):
        return self.addr

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

load_relocations()
