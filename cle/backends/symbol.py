from __future__ import print_function
import subprocess
import ctypes

from ..address_translator import AT

try:
    import claripy
except ImportError:
    claripy = None


class Symbol(object):
    """
    Representation of a symbol from a binary file. Smart enough to rebase itself.

    There should never be more than one Symbol instance representing a single symbol. To make sure of this, only use
    the :meth:`cle.backends.Backend.get_symbol()` to create new symbols.

    :ivar owner_obj:        The object that contains this symbol
    :vartype owner_obj:     cle.backends.Backend
    :ivar str name:         The name of this symbol
    :ivar int addr:         The un-based address of this symbol, an RVA
    :iver int size:         The size of this symbol
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

    def __init__(self, owner, name, relative_addr, size, sym_type):
        """
        Not documenting this since if you try calling it, you're wrong.
        """
        super(Symbol, self).__init__()
        self.owner_obj = owner
        self.name = name
        self.relative_addr = relative_addr
        self.size = size
        self.type = sym_type
        self.resolved = False
        self.resolvedby = None
        if (claripy and isinstance(self.relative_addr, claripy.ast.Base)) or self.relative_addr != 0:
            self.owner_obj._symbols_by_addr[self.relative_addr] = self
            if "MachO" not in str(type(self.owner_obj)): # Type comparison without adding dependency. MachO has no demangled_names.
                if self.name != self.demangled_name: # populating demangled_names
                        self.owner_obj.demangled_names[self.name] = self.demangled_name

    def __repr__(self):
        if self.is_import:
            return '<Symbol "%s" in %s (import)>' % (self.name, self.owner_obj.provides)
        else:
            return '<Symbol "%s" in %s at %#x>' % (self.name, self.owner_obj.provides, self.rebased_addr)

    def resolve(self, obj):
        self.resolved = True
        self.resolvedby = obj
        self.owner_obj.resolved_imports.append(self)

    @property
    def rebased_addr(self):
        """
        The address of this symbol in the global memory space
        """
        return AT.from_rva(self.relative_addr, self.owner_obj).to_mva()

    @property
    def linked_addr(self):
        return AT.from_rva(self.relative_addr, self.owner_obj).to_lva()

    warned_addr = False

    @property
    def addr(self):
        if not Symbol.warned_addr:
            print("\x1b[31;1mDeprecation warning: Symbol.addr is ambiguous, please use relative_addr, linked_addr, or rebased_addr\x1b[0m")
            Symbol.warned_addr = True
        return self.linked_addr

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
    is_weak = False
    is_extern = False
    is_forward = False

    @property
    def demangled_name(self):
        """
        The name of this symbol, run through a C++ demangler if mangling is found.
        """
        # make sure it's mangled
        if self.name.startswith("_Z"):
            name = self.name
            if '@@' in self.name:
                name = self.name.split("@@")[0]
            return _demangle(name)

        return self.name

    def resolve_forwarder(self):
        """
        If this symbol is a forwarding export, return the symbol the forwarding refers to, or None if it cannot be found.
        """
        return self

    def _find_any_lib(*choices):
        for choice in choices:
            lib = ctypes.util.find_library(choice)
            if lib is not None:
                return lib
        raise Exception("Could not find any libraries for {}".format(choices))

    libc = ctypes.CDLL(_find_any_lib('c'))
    libc.free.argtypes = [ctypes.c_void_p]

    libcxx = ctypes.CDLL(_find_any_lib('c++', 'stdc++'))
    libcxx["__cxa_demangle"].restype = ctypes.c_char_p # Dict notation is necessary here, since ctypes would otherwise prepend the classname to the symbol property. Why?

    def _demangle(mangled_name):
        """
        Name demangling using __cxa_demangle
        """
        if not mangled_name.startswith(b'_Z'):
            return mangled_name

        mangled_name_p = ctypes.c_char_p(mangled_name)
        status = ctypes.c_int()
        retval = libcxx.__cxa_demangle(
            mangled_name_p,
            None,
            None,
            ctypes.pointer(status)
        )
        try:
            demangled = retval.value
        finally:
            libc.free(retval)

        if status.value == 0:
            return demangled
        elif status.value == -1:
            raise Exception("Memory allocation failure while demangling symbol")
        elif status.value == -2:
            raise Exception("Invalid Name: {}".format(mangled_name))
        elif status.value == -3:
            raise Exception("One of the arguments to name demangling is invalid")
        else:
            raise Exception("Unknown status code: {}".format(status.value))
