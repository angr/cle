from __future__ import print_function
import subprocess
import logging

from ..address_translator import AT

l = logging.getLogger('cle.backends.symbol')


class Symbol:
    """
    Representation of a symbol from a binary file. Smart enough to rebase itself.

    There should never be more than one Symbol instance representing a single symbol. To make sure of this, only use
    the :meth:`cle.backends.Backend.get_symbol()` to create new symbols.

    :ivar owner:            The object that contains this symbol
    :vartype owner:         cle.backends.Backend
    :ivar str name:         The name of this symbol
    :ivar int addr:         The un-based address of this symbol, an RVA
    :ivar int size:         The size of this symbol
    :ivar int type:         The type of this symbol as one of SYMBOL.TYPE_*
    :ivar bool resolved:    Whether this import symbol has been resolved to a real symbol
    :ivar resolvedby:       The real symbol this import symbol has been resolve to
    :vartype resolvedby:    None or cle.backends.Symbol
    :ivar str resolvewith:  The name of the library we must use to resolve this symbol, or None if none is required.
    """

    # enum for symbol types
    TYPE_OTHER = 0
    TYPE_NONE = 1
    TYPE_FUNCTION = 2
    TYPE_OBJECT = 3
    TYPE_SECTION = 4
    TYPE_TLS_OBJECT = 5

    def __init__(self, owner, name, relative_addr, size, sym_type):
        """
        Not documenting this since if you try calling it, you're wrong.
        """
        self.owner = owner
        self.name = name
        self.relative_addr = relative_addr
        self.size = size
        self.type = sym_type
        self.resolved = False
        self.resolvedby = None

        # would be nice if we could populate demangled_names here...
        #demangled = self.demangled_name
        #if demangled is not None:
        #    self.owner.demangled_names[self.name] = demangled

    def __repr__(self):
        if self.is_import:
            return '<Symbol "%s" in %s (import)>' % (self.name, self.owner.provides)
        else:
            return '<Symbol "%s" in %s at %#x>' % (self.name, self.owner.provides, self.rebased_addr)

    def resolve(self, obj):
        self.resolved = True
        self.resolvedby = obj
        self.owner.resolved_imports.append(self)

    @property
    def rebased_addr(self):
        """
        The address of this symbol in the global memory space
        """
        return AT.from_rva(self.relative_addr, self.owner).to_mva()

    @property
    def linked_addr(self):
        return AT.from_rva(self.relative_addr, self.owner).to_lva()

    @property
    def is_function(self):
        """
        Whether this symbol is a function
        """
        return self.type == Symbol.TYPE_FUNCTION

    # These may be overridden in subclasses
    is_static = False
    is_common = False
    is_import = False
    is_export = False
    is_local = False
    is_weak = False
    is_extern = False
    is_forward = False

    @property
    def demangled_name(self):
        """
        The name of this symbol, run through a C++ demangler

        Warning: this calls out to the external program `c++filt` and will fail loudly if it's not installed
        """
        # make sure it's mangled
        if self.name.startswith("_Z"):
            name = self.name
            if '@@' in self.name:
                name = self.name.split("@@")[0]
            args = ['c++filt']
            args.append(name)
            pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            demangled = stdout.decode().split("\n")

            if demangled:
                return demangled[0]

        return self.name

    def resolve_forwarder(self):
        """
        If this symbol is a forwarding export, return the symbol the forwarding refers to, or None if it cannot be found.
        """
        return self

    # compatibility layer

    _complained_owner = False

    @property
    def owner_obj(self):
        if not Symbol._complained_owner:
            Symbol._complained_owner = True
            l.critical("Deprecation warning: use symbol.owner instead of symbol.owner_obj")
        return self.owner
