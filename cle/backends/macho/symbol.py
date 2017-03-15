# -*-coding:utf8 -*-

# This file is part of Mach-O Loader for CLE.
# Contributed December 2016 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).

from .. import Symbol

import logging
l = logging.getLogger('cle.backends.macho.symbol')

# some constants:
SYMBOL_TYPE_UNDEF = 0x0
SYMBOL_TYPE_ABS = 0x2
SYMBOL_TYPE_SECT = 0xe
SYMBOL_TYPE_PBUD = 0xc
SYMBOL_TYPE_INDIR = 0xa

TYPE_LOOKUP = {
        SYMBOL_TYPE_UNDEF: Symbol.TYPE_NONE,
        SYMBOL_TYPE_SECT: Symbol.TYPE_SECTION
}

LIBRARY_ORDINAL_SELF = 0x0
LIBRARY_ORDINAL_MAX = 0xfd
LIBRARY_ORDINAL_OLD_MAX = 0xfe
LIBRARY_ORDINAL_DYN_LOOKUP = 0xfe
LIBRARY_ORDINAL_EXECUTABLE = 0xff


class MachOSymbol(Symbol):
    """
    Base class for Mach-O symbols. Made to be (somewhat) compatible with backends.Symbol.
    Note that ELF-specific fields from backends.Symbol are not used and semantics of the remaining fields differs in
    many cases. As a result most stock functionality from Angr and related libraries WILL NOT WORK PROPERLY on
    MachOSymbol.

    Much of the code below is based on heuristics as official documentation is sparse, consider yourself warned!
    """

    def is_import(self):
        return self.sym_type == SYMBOL_TYPE_UNDEF and self.library_ordinal != LIBRARY_ORDINAL_SELF

    def is_export(self):
        return self._is_export

    def is_weak(self):
        # compare https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachOTopics/1-Articles/executing_files.html
        return self.is_weak_referenced

    def __init__(self, owner, name, addr, symtab_offset, macho_type, section_number, description, value, library_name=None,
                 segment_name=None, section_name=None, is_export=None):

        # Note that setting size = owner.arch.bytes has been directly taken over from the PE backend,
        # there is no meaningful definition of a symbol's size so I assume the size of an address counts here
        # Note also that addr will be the address of a symbols __got or __nl_symbol_ptr entry, not the address of a stub
        # pointing to the symobl.
        # Stub addresses must be obtained through some sort of higher-level analysis
        # note that a symbols name may not be unique!
        super(MachOSymbol, self).__init__(owner,
                name,
                addr,
                owner.arch.bytes,
                TYPE_LOOKUP.get(macho_type, Symbol.TYPE_OTHER))

        # store the mach-o properties
        self.symtab_offset = symtab_offset
        self.n_type = macho_type
        self.n_sect = section_number
        self.n_desc = description
        self.n_value = value  # mach-o uses this as a multi-purpose field depending on type flags and whatnot
        self.library_name = library_name  # if this is an import this field *may* contain a string specifying the library name
        self.segment_name = segment_name  # if this entry has a section number the associated segment name is stored here
        self.section_name = section_name  # if this entry has a section number the associated section name is stored here
        self._is_export = is_export  # if the symbol turns out to be an export this should be set to true or false if not. None means "Unknown"
        self.bind_xrefs = []  # XREFs discovered during binding of the symbol
        self.symbol_stubs = []  # starting addresses of stubs that resolve to this symbol - note that this must be obtained through an analysis of some sort

    def is_function(self):
        # Incompatibility to CLE
        l.warn("It is not possible to decide wether a symbol is a function or not for MachOSymbols")
        return False

    def rebased_addr(self):
        l.warn("Rebasing not implemented for Mach-O")
        return self.addr

    def resolve(self, obj):
        # Incompatibility to CLE
        pass  # Mach-O cannot be resolved like this as the whole binary is involved

    def demangled_name(self):
        return self.name  # it is not THAT easy with Mach-O

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
