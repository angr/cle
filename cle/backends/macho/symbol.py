# -*-coding:utf8 -*-

# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/) and updated in September 2019.

from .. import Symbol, SymbolType

import logging
l = logging.getLogger(name=__name__)

# some constants:
SYMBOL_TYPE_UNDEF = 0x0
SYMBOL_TYPE_ABS = 0x2
SYMBOL_TYPE_SECT = 0xe
SYMBOL_TYPE_PBUD = 0xc
SYMBOL_TYPE_INDIR = 0xa

LIBRARY_ORDINAL_SELF = 0x0
LIBRARY_ORDINAL_MAX = 0xfd
LIBRARY_ORDINAL_OLD_MAX = 0xfe
LIBRARY_ORDINAL_DYN_LOOKUP = 0xfe
LIBRARY_ORDINAL_EXECUTABLE = 0xff

class AbstractMachOSymbol(Symbol):
    """
    Base class for Mach-O symbols.
    Defines the minimum common properties all types of mach-o symbols must have
    """

    def __init__(self, owner, name, relative_addr, size, sym_type):
        super().__init__(owner,name,relative_addr,size,sym_type)

        # additional properties
        self.bind_xrefs = []  # XREFs discovered during binding of the symbol
        self.symbol_stubs = []  # starting addresses of stubs that resolve to this symbol - note that this must be obtained through an analysis of some sort

    @property
    def library_ordinal(self):
        return None

    @property
    def is_stab(self):
        return False

class SymbolTableSymbol(AbstractMachOSymbol):
    """
    "Regular" symbol. Made to be (somewhat) compatible with backends.Symbol.
    A SymbolTableSymbol is an entry in the binary's symbol table.

    Note that ELF-specific fields from backends.Symbol are not used and semantics of the remaining fields differ in
    many cases. As a result most stock functionality from Angr and related libraries WILL NOT WORK PROPERLY on
    MachOSymbol.

    Much of the code below is based on heuristics as official documentation is sparse, consider yourself warned!
    """

    def __init__(self, owner, symtab_offset, n_strx, n_type, n_sect, n_desc, n_value):
        # Note 1: Setting size = owner.arch.bytes has been directly taken over from the PE backend,
        # there is no meaningful definition of a symbol's size so I assume the size of an address counts here
        # Note 2: relative_addr will be the address of a symbols __got or __nl_symbol_ptr entry, not the address of a stub
        # pointing to the symobl.
        # Stub addresses must be obtained through some sort of higher-level analysis
        # Note 3: A symbols name may not be unique!
        # Note 4: The symbol type of all symbols is SymbolType.TYPE_OTHER because without docs I was unable to proplerly map Mach-O symbol types to CLE's notion of a symbol type

        # store the mach-o properties, all these are raw values straight from the binary
        self.symtab_offset = symtab_offset # offset from the start of the symbol table
        self.n_type = n_type # n_type field from the symbol table
        self.n_sect = n_sect # n_sect field from the symbol table
        self.n_desc = n_desc # n_desc  field from the symbol table
        self.n_value = n_value  # n_value field from the symbol table.
        self.n_strx = n_strx # index into the string table



        # now we may call super
        # however we cannot access any properties yet that would touch superclass-initialized attributes
        # so we have to repeat some work
        super().__init__(owner,
               owner.get_string(n_strx).decode('utf-8') if n_strx != 0 else "",
                self.value,
                owner.arch.bytes,
                SymbolType.TYPE_OTHER)

        # set further fields
        self.is_import = self.sym_type == SYMBOL_TYPE_UNDEF and self.is_external and self.library_ordinal != LIBRARY_ORDINAL_SELF
        self.is_export = self.name in self.owner.exports_by_name

    @property
    def library_name(self):
        if self.is_import:
            if LIBRARY_ORDINAL_DYN_LOOKUP == self.library_ordinal:
                l.warning("LIBRARY_ORDINAL_DYN_LOOKUP found, cannot handle")
                return None
            else:
                return self.owner.imported_libraries[self.library_ordinal]
        return None

    @property
    def segment_name(self):
        if self.sym_type == SYMBOL_TYPE_SECT:
            return self.owner.sections_by_ordinal[self.n_sect].segname
        else:
            return None

    @property
    def section_name(self):
        if self.sym_type == SYMBOL_TYPE_SECT:
            return self.owner.sections_by_ordinal[self.n_sect].sectname
        else:
            return None

    @property
    def value(self):
        if self.sym_type == SYMBOL_TYPE_INDIR:
            return 0
        else:
            return self.n_value

    @property
    def referenced_symbol_index(self):
        """For indirect symbols n_value contains an index into the string table indicating the referenced
        symbol's name"""
        if self.sym_type == SYMBOL_TYPE_INDIR:
            return self.n_value
        else:
            return None


    def is_weak(self):
        # compare https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html
        return self.is_weak_referenced

    def is_function(self):
        # Incompatibility to CLE
        l.warning("It is not possible to decide wether a symbol is a function or not for MachOSymbols")
        return False

    @property
    def rebased_addr(self):
        l.warning("Rebasing not implemented for Mach-O")
        return self.linked_addr

    def resolve(self, obj):
        # Incompatibility to CLE
        pass  # Mach-O cannot be resolved like this as the whole binary is involved

    # real symbols have properties, mach-o symbols have plenty of them:
    @property
    def is_stab(self):
        return self.n_type & 0xe0

    @property
    def is_private_external(self):
        return self.n_type & 0x10

    @property
    def is_external(self):
        return self.n_type & 0x01

    @property
    def sym_type(self):  # cannot be called "type" as that shadows a builtin variable from Symbol
        if self.is_stab:
            return self.n_type
        else:
            return self.n_type & 0x0e

    @property
    def is_common(self):
        return self.is_external and self.sym_type == SYMBOL_TYPE_UNDEF and self.n_value != 0

    @property
    def common_align(self):
        return None if not self.is_common else ((self.n_desc) >> 8) & 0x0f

    @property
    def reference_type(self):
        return self.n_desc & 0x7 if self.sym_type == SYMBOL_TYPE_UNDEF else None

    @property
    def library_ordinal(self):
        return ((self.n_desc) >> 8) & 0xff

    @property
    def is_no_dead_strip(self):
        return self.n_desc & 0x0020

    @property
    def is_desc_discarded(self):
        return self.is_no_dead_strip

    @property
    def is_weak_referenced(self):
        return self.n_desc & 0x0040

    @property
    def is_weak_defined(self):
        return self.n_desc & 0x0080

    @property
    def is_reference_to_weak(self):
        return self.n_desc & 0x0080

    @property
    def is_thumb_definition(self):
        return self.n_desc & 0x0008

    @property
    def is_symbol_resolver(self):
        return self.n_desc & 0x0100

    @property
    def is_alt_entry(self):
        return self.n_desc & 0x0200


class BindingSymbol(AbstractMachOSymbol):
    """
    "Binding" symbol. Made to be (somewhat) compatible with backends.Symbol.
    A BindingSymbol is an imported symbol discovered during the binding process.

    Note that ELF-specific fields from backends.Symbol are not used and semantics of the remaining fields differ in
    many cases. As a result most stock functionality from Angr and related libraries WILL NOT WORK PROPERLY on
    MachOSymbol.

    Much of the code below is based on heuristics as official documentation is sparse, consider yourself warned!
    """



    def __init__(self, owner, name,lib_ordinal):
        # Note 1: Setting size = owner.arch.bytes has been directly taken over from the PE backend,
        # there is no meaningful definition of a symbol's size so I assume the size of an address counts here
        # Note 2: relative_addr will be the address of a symbols __got or __nl_symbol_ptr entry, not the address of a stub
        # pointing to the symobl.
        # Stub addresses must be obtained through some sort of higher-level analysis
        # Note 3: A symbols name may not be unique!
        # Note 4: The symbol type of all symbols is SymbolType.TYPE_OTHER because without docs I was unable to problerly map Mach-O symbol types to CLE's notion of a symbol type

        # store the mach-o properties, all these are raw values straight from the binary
        self.lib_ordinal = lib_ordinal

        # now we may call super
        # however we cannot access any properties yet that would touch superclass-initialized attributes
        # so we have to repeat some work
        super().__init__(owner,
                                                name,
                                                0,
                                                owner.arch.bytes,
                                                SymbolType.TYPE_OTHER)

        # set further fields
        self.is_import = True # this is always an import
        self.is_export = self.name in self.owner_obj.exports_by_name

    @property
    def library_name(self):
        if LIBRARY_ORDINAL_DYN_LOOKUP == self.lib_ordinal:
            l.warning("LIBRARY_ORDINAL_DYN_LOOKUP found, cannot handle")
            return None

        return self.owner_obj.imported_libraries[self.lib_ordinal]


    def is_function(self):
        # Incompatibility to CLE
        l.warning("It is not possible to decide wether a symbol is a function or not for MachOSymbols")
        return False

    @property
    def rebased_addr(self):
        l.warning("Rebasing not implemented for Mach-O")
        return self.linked_addr

    def resolve(self, obj):
        # Incompatibility to CLE
        pass  # Mach-O cannot be resolved like this as the whole binary is involved

    def demangled_name(self):
        return self.name  # it is not THAT easy with Mach-O

    @property
    def library_ordinal(self):
        return self.lib_ordinal
