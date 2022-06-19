from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import describe_form_class, describe_reg_name
from elftools.dwarf.locationlists import LocationEntry, LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser, DW_OP_name2opcode

import cle.backends.elf.parser as abi_parser
from .location import get_register_from_expr, get_dwarf_from_expr
from .types import ClassType
from .variable_type import VariableType
from ..corpus import Corpus
from .decorator import cache_type

import os
import re
import json
import logging
import sys

l = logging.getLogger(name=__name__)


class ElfCorpus(Corpus):
    """
    Represents a Json corpus for an ELF file, derived from DWARF.
    """

    def __init__(self, *args, **kwargs):
        self.loc_parser = None
        self.arch = kwargs.get("arch")
        self.parser = getattr(abi_parser, self.arch.name, None)
        self.symbols = kwargs.get("symbols")
        # Default don't include double underscore (private) variables
        self.include_private = kwargs.get("include_private", False)
        super().__init__(*args, **kwargs)

        # self.types is cache of type id -> json
        # Types cache of die.offset -> type id
        self._types = {}
        self._types_seen = set()

        # Keep track of ids we have parsed before (underlying types)
        self.lookup = set()

    def parse_variable(self, die, flags=None):
        """
        Add a global variable parsed from the dwarf.
        """
        # static globals - internal linkage but file scope, only seen by CU where declared
        # This variable cannot be part of an ABI discussion, like a local variable
        if ("DW_AT_external" not in die.attributes) or (
            "DW_AT_external" in die.attributes
            and die.attributes["DW_AT_external"].value == 0
        ):
            direction = "none"
            return

        # DW_AT_external attribute if the variable is visible outside of its enclosing CU
        entry = {
            "name": self.get_name(die),
            "location": "var",
        }
        # Stop parsing if we've seen it before
        if entry["name"] in self.variables:
            return

        entry.update(self.parse_underlying_type(die))

        # DW_AT_declaration if present is an export, otherwise is an import
        direction = "export"
        if "DW_AT_declaration" in die.attributes:
            direction = "import"

        entry["direction"] = direction
        entry = self.add_flags(entry, flags)
        self.variables[entry["name"]] = entry
        return entry

    def add_dwarf_information_entry(self, die):
        """
        Parse DIEs that aren't functions (subprograms) and variables.

        I started parsing recursively here, but I think each type function
        should handle parsing its own children.
        """
        self.parse_die(die)
        if die.has_children:
            for child in die.iter_children():
                self.add_dwarf_information_entry(child)

    def parse_die(self, die):
        """
        This top level function is things that we care about, e.g.,
        parsing a function will append a function entry, a variable
        a variable entry, and other tags mentioned here drill down to those.
        """
        # Have we seen it before?
        if die.offset in self.lookup:
            return {}
        self.lookup.add(die.offset)

        # We only care about variable and functions
        if die.tag == "DW_TAG_variable":
            return self.parse_variable(die)

        if die.tag == "DW_TAG_subprogram":
            return self.parse_subprogram(die)

    def parse_children(self, die):
        for child in die.iter_children():
            if not child.tag:
                continue
            self.parse_die(child)

    def add_flags(self, entry, flags=None):
        """
        Given a list of string flags, add them to an entry with value True
        """
        if not flags:
            return entry
        for flag in flags:
            entry[flag] = True
        return entry

    def parse_call_site(self, die, parent):
        """
        Parse a call site
        """
        entry = {"class": "Function"}
        # The abstract origin points to the function
        if "DW_AT_abstract_origin" in die.attributes:
            origin = self.type_die_lookup.get(
                die.attributes["DW_AT_abstract_origin"].value
            )

            # We can't look up the callsite in this dwarf info
            if origin:
                entry.update({"name": self.get_name(origin)})

        params = []
        for child in die.iter_children():
            if child.tag in [
                "DW_TAG_GNU_call_site_parameter",
                "DW_TAG_call_site_parameter",
            ]:
                param = self.parse_call_site_parameter(child)
                if param:
                    params.append(param)
            else:
                raise Exception("Unknown call site parameter!:\n%s" % child)

        if params:
            entry["parameters"] = params
        self.callsites.append(entry)
        return entry

    def parse_inlined_subroutine(self, die):
        """
        Parse an inlined suboutine
        """
        if "DW_AT_abstract_origin" in die.attributes:
            origin = self.type_die_lookup.get(
                die.attributes["DW_AT_abstract_origin"].value
            )
            if origin:
                return self.parse_subprogram(origin)
            # We cannot trace the abstract origin
            else:
                return {"type": "unknown"}

        # This is a type we don't know - for development should be Ipython
        return {"type": "unknown"}

    def parse_call_site_parameter(self, die):
        """
        Given a callsite parameter, parse the dwarf expression
        """
        param = {}
        loc = self.parse_location(die)

        # Most callsite params just have a location and value
        if not loc:
            loc = self.parse_dwarf_location(die)
        if loc:
            param["location"] = loc

        # Each DW_TAG_call_site_parameter entry may have a DW_AT_call_value
        # attribute which is a DWARF expression which when evaluated yields the value
        # of the parameter at the time of the call. Note that these can return
        # registers, address, or values, we can parse further if needed.
        # https://dwarfstd.org/doc/DWARF5.pdf#chap%3ADWOPlitzero
        # The location imho seems sufficient for now.
        # if "DW_AT_GNU_call_site_value" in die.attributes:
        #    expr_parser = DWARFExprParser(die.dwarfinfo.structs)
        #    expr = die.attributes["DW_AT_GNU_call_site_value"].value
        #    print(get_dwarf_from_expr(expr, die.dwarfinfo.structs, cu_offset=die.cu.cu_offset))
        return param

    def parse_reference_type(self, die):
        """
        Parse a reference type
        """
        return self.parse_underlying_type(die)

    def parse_pointer_type(self, die, parent, allocator=None, flags=None):
        """
        This is hit parsing a pointer function param

        The parent (from the type) will have the name
        """
        parent = parent or die

        # Use the parent for name or the die
        name = self.get_name(parent)
        if name == "unknown":
            name = self.get_name(die)

        entry = {
            "class": "Pointer",
            "size": self.get_size(die),
            "underlying_type": self.parse_underlying_type(die, allocator=allocator),
            "direction": "both",
        }
        if name != "unknown":
            entry["name"] = name
        entry = self.add_flags(entry, flags)

        # If we have an allocator passed from parsing a subprogram
        if allocator:
            entry["location"] = allocator.get_next_int_register()
        return entry

    def parse_formal_parameter(self, die, allocator, flags=None):
        """
        Parse a formal parameter
        """
        # Size isn't included here because will be present with underlying type
        entry = {}
        name = self.get_name(die)
        if name != "unknown":
            entry["name"] = name

        # It looks like there are cases of formal parameter having type of
        # a formal parameter - see libgettext.so
        entry.update(self.parse_underlying_type(die))

        loc = None
        if entry.get("class") == "Pointer":
            loc = allocator.get_next_int_register()
        else:
            loc = self.parse_location(die, allocator=allocator)

        # Only add location if we know it!
        if loc:
            entry["location"] = loc
        entry = self.add_flags(entry, flags)
        return entry

    def parse_subprogram(self, die):
        """
        Add a function (subprogram) parsed from DWARF

        The design of this parser is assuming we want all things nested under
        functions, hence why we parse the subprogram children here to find
        the rest.
        """
        name = self.get_name(die)
        if (
            self.symbols
            and name not in self.symbols
            or not self.include_private
            and name.startswith("__")
        ):
            return

        # If has DW_TAG_external, we know it's external outside of this CU
        if "DW_AT_external" not in die.attributes:
            return

        # TODO see page 92 of https://dwarfstd.org/doc/DWARF4.pdf
        # need to parse virtual functions and other attributes
        entry = {"name": name, "class": "Function"}
        if name in self.symbols:
            entry["direction"] = self.symbols[name]

        # Set the allocator on the level of the function
        allocator = None
        if self.parser:
            allocator = self.parser.get_allocator()

        # Parse the return value
        return_value = None
        if "DW_AT_type" in die.attributes:
            return_value = self.parse_underlying_type(die)
            return_value["direction"] = "export"
            loc = self.parse_location(die, underlying_type=return_value, is_return=True)
            if loc:
                return_value["location"] = loc

        params = []

        # Hold previous child for modifiers
        param = None
        for child in die.iter_children():

            if not child.tag:
                continue

            # can either be inlined subroutine or format parameter
            if child.tag in ["DW_TAG_formal_parameter", "DW_TAG_template_value_param"]:
                param = self.parse_formal_parameter(child, allocator=allocator)

            elif child.tag == "DW_TAG_inlined_subroutine":
                # If we have an abstract origin we know type for
                child = self.type_die_lookup.get(
                    child.attributes["DW_AT_abstract_origin"].value
                )

                if not child:
                    continue

                # This isn't a parameter but a subroutine, separate
                if child.tag == "DW_TAG_subprogram":
                    self.parse_subprogram(child)

                # subprogram -> child inline subroutine -> call site parameter
                elif child.tag in [
                    "DW_TAG_GNU_call_site_parameter",
                    "DW_TAG_call_site_parameter",
                ]:
                    param = self.parse_call_site_parameter(child)

            # Variable parameter list? E.g., this is present for print after a formal param
            elif child.tag == "DW_TAG_unspecified_parameters":
                continue

            # These usually aren't seen outside the CU
            elif child.tag == "DW_TAG_variable":
                self.parse_variable(child)

            elif child.tag == "DW_TAG_union_type":
                param = self.parse_union_type(child)

            elif child.tag == "DW_TAG_enumeration_type":
                param = self.parse_enumeration_type(child)

            elif child.tag == "DW_TAG_array_type":
                param = self.parse_array_type(child)

            elif child.tag in ["DW_TAG_const_type", "DW_TAG_constant"]:
                param = self.parse_underlying_type(child, flags=["constant"])
            elif child.tag == "DW_TAG_volatile_type":
                param = self.parse_underlying_type(child, flags=["volatile"])
            elif child.tag == "DW_TAG_restrictive_type":
                param = self.parse_underlying_type(child, flags=["restrictive"])

            elif child.tag == "DW_TAG_structure_type":
                param = self.parse_structure_type(child)

            elif child.tag == "DW_TAG_pointer_type":
                param = self.parse_pointer_type(child, parent=die, allocator=allocator)

            # TODO should we be passing the allocator here?
            elif child.tag == "DW_TAG_imported_declaration":
                param = self.parse_imported_declaration(child)

            # TODO should we be passing the same allocator here?
            elif child.tag == "DW_TAG_subprogram":
                param = self.parse_subprogram(child)

            # Call sites
            elif child.tag in ["DW_TAG_GNU_call_site", "DW_TAG_call_site"]:
                param = self.parse_call_site(child, die)

            # TODO is this only external stuff?
            elif child.tag == "DW_TAG_lexical_block":
                self.parse_lexical_block(child)

            # Skip these for now (we will likely need to re-add some to parse)
            elif (
                child.tag
                in [
                    "DW_TAG_typedef",
                    "DW_TAG_label",
                    "DW_TAG_template_type_param",
                    "DW_TAG_imported_module",
                    "DW_TAG_subroutine_type",
                    "DW_TAG_common_block",
                ]
                or not child.tag
            ):
                continue

            else:
                # for development should be Ipython
                continue
            if param:
                if "direction" not in param:
                    param["direction"] = "import"

                params.append(param)
                param = None
        if params:
            entry["parameters"] = params
        if return_value:
            entry["return"] = return_value

        self.functions.append(entry)
        return entry

    # TAGs to parse
    def parse_lexical_block(self, die, code=None):
        """
        Lexical blocks typically have variable children?

        A lexical block is a bracketed sequence of source statements that may contain any number
        of declarations. In some languages (including C and C++), blocks can be nested within3
        other blocks to any depth.
        """
        for child in die.iter_children():
            if child.tag == "DW_TAG_variable":
                self.parse_variable(child)
            elif child.tag in ["DW_TAG_GNU_call_site", "DW_TAG_call_site"]:
                self.parse_call_site(child, parent=die)
            elif child.tag == "DW_TAG_subprogram":
                self.parse_subprogram(child)

            # We found a loop
            elif child.tag == "DW_AT_lexical_block":
                if code == die.abbrev_code:
                    return
                return self.parse_lexical_block(child, die.abbrev_code)

    def parse_structure_type(self, die, flags=None):
        """
        Parse a structure type.
        """
        # The size here includes padding
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
            "class": "Struct",
        }
        fields = []
        for child in die.iter_children():

            # DIE None
            if not child.tag:
                continue

            field = self.parse_member(child)
            # Our default is import but Matt wants struct param fields to be exports
            if "direction" not in field or field["direction"] != "both":
                field["direction"] = "export"
            fields.append(field)
        if fields:
            entry["fields"] = fields
        entry = self.add_flags(entry, flags)
        return entry

    def parse_string_type(self, die, flags=None):
        """
        In Fortran the char size 1 is presented as a string
        """
        # The size here includes padding
        entry = {
            "type": "char",
            "size": self.get_size(die),
            "class": self.add_class(die),
            "direction": "import",
        }
        entry = self.add_flags(entry, flags)
        return entry

    def parse_base_type(self, die, flags=None):
        """
        Parse a base type.
        """
        # The size here includes padding
        entry = {
            "type": self.get_name(die),
            "size": self.get_size(die),
            "class": self.add_class(die),
            "direction": "import",
        }
        entry = self.add_flags(entry, flags)
        return entry

    def parse_union_type(self, die, flags=None):
        """
        Parse a union type.
        """
        # The size here includes padding
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
            "class": "Union",
        }

        # TODO An incomplete union won't have byte size attribute and will have DW_AT_declaration attribute.
        # page https://dwarfstd.org/doc/DWARF4.pdf 85

        # Parse children (members of the union)
        fields = []
        for child in die.iter_children():
            if not child.tag:
                continue
            fields.append(self.parse_member(child))

        if fields:
            entry["fields"] = fields
        entry = self.add_flags(entry, flags)
        return entry

    def parse_location(
        self, die, underlying_type=None, allocator=None, is_return=False
    ):
        """
        Look to see if the DIE has DW_AT_location, and if so, parse to get
        registers. The loc_parser is called by elf.py (once) and addde
        to the corpus here when it is parsing DIEs.
        """
        # Envar to control (force) not using dwarf locations
        experimental_parsing = True
        # = os.environ.get("CLE_ELF_EXPERIMENTAL_PARSING") is not None

        # Can we parse based on an underlying type and arch?
        if experimental_parsing:
            loc = None
            if not self.parser:
                sys.exit(
                    "Experimental parsing selected by ABI for %s is not supported yet."
                    % self.arch.name
                )
            underlying_type = underlying_type or self.parse_underlying_type(
                die, allocator=allocator
            )
            allocator = allocator or self.parser.get_return_allocator()
            if underlying_type:
                # Get the actual type information
                typ = self.types[underlying_type["type"]]
                loc = self.parser.classify(
                    typ, die=die, allocator=allocator, types=self.types
                )
            return loc

        # Without experimental uses dwarf location lists
        return self.parse_dwarf_location(die)

    def parse_dwarf_location(self, die):
        """
        Get location information from dwarf location lists
        """
        if "DW_AT_location" not in die.attributes:
            return
        attr = die.attributes["DW_AT_location"]
        if self.loc_parser.attribute_has_location(attr, die.cu["version"]):
            loc = self.loc_parser.parse_from_attribute(attr, die.cu["version"])

            # Attribute itself contains location information
            if isinstance(loc, LocationExpr):
                loc = get_register_from_expr(
                    loc.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset
                )
                # The first entry is the register
                return self.parse_register(loc[0])

            # List is reference to .debug_loc section
            elif isinstance(loc, list):
                loc = self.get_loclist(loc, die)
                return self.parse_register(loc[0][0])

    def parse_register(self, register):
        """
        Given the first register entry, remove dwarf
        """
        # DW_OP_fbreg is signed LEB128 offset from  the DW_AT_frame_base address of the current function.
        if "DW_OP_fbreg" in register:
            return "framebase" + register.split(":")[-1].strip()
        # If we have a ( ) this is the register name
        if re.search(r"\((.*?)\)", register):
            return "%" + re.sub(
                "(\(|\))", "", re.search(r"\((.*?)\)", register).group(0)
            )
        # Still need to parse
        if register == "null":
            return None
        return register

    def get_loclist(self, loclist, die):
        """
        Get the parsed location list

        # TODO double check that we can use the cu/dwarfinfo off of the die instance
        """
        registers = []
        for loc_entity in loclist:
            if isinstance(loc_entity, LocationEntry):
                registers.append(
                    get_register_from_expr(
                        loc_entity.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset
                    )
                )
            else:
                registers.append(str(loc_entity))
        return registers

    def parse_member(self, die):
        """
        Parse a member, typically belonging to a union (something else?)
        """
        entry = {"name": self.get_name(die)}
        underlying_type = self.parse_underlying_type(die)
        if underlying_type:
            entry.update(underlying_type)
        return entry

    def parse_array_type(self, die, parent=None, flags=None):
        """
        Get an entry for an array.
        """
        parent = parent or die

        # TODO what should I do if there is DW_AT_sibling? Use it for something instead?
        entry = {"class": "Array", "name": self.get_name(die)}

        # Get the type of the members
        array_type = self.parse_underlying_type(die)

        # TODO we might want to handle order
        # This can be DW_AT_col_order or DW_AT_row_order, and if not present
        # We use the language default
        if "DW_AT_ordering" in die.attributes:
            entry["order"] = die.attributes["DW_AT_ordering"].value

        # Case 1: the each member of the array uses a non-traditional storage
        member_size = self._find_nontraditional_size(die)

        # Children are the members of the array
        entries = []
        children = list(die.iter_children())

        size = 0
        total_size = 0
        total_count = 0
        for child in children:
            if not child.tag:
                continue
            member = None

            # Each array dimension is DW_TAG_subrange_type or DW_TAG_enumeration_type
            if child.tag == "DW_TAG_subrange_type":
                member = self.parse_subrange_type(child)
            elif child.tag == "DW_TAG_enumeration_type":
                member = self.parse_enumeration_type(child)
            else:
                l.warning("Unknown array member tag %s" % child.tag)

            if not member:
                continue

            count = member.get("count", 0)
            size = member.get("size") or member_size
            if count != "unknown" and size:
                total_size += count * size
            entries.append(member)

        entry["size"] = total_size
        entry["count"] = total_count

        # Update info with the parent
        entry.update(
            {
                "name": self.get_name(parent),
                "class": "Array",
            }
        )
        entry = self.add_flags(entry, flags)
        if "type" in array_type:
            entry["type"] = array_type["type"]
        return entry

    def parse_enumeration_type(self, die, flags=None):
        """
        Parse an enumeration type
        """
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
        }
        underlying_type = self.parse_underlying_type(die)
        entry.update(underlying_type)
        entry["class"] = "Enum"

        fields = []
        for child in die.iter_children():
            if not die.tag:
                continue
            field = {
                "name": self.get_name(child),
                "value": child.attributes["DW_AT_const_value"].value,
            }
            fields.append(field)
        if fields:
            entry["fields"] = fields
        entry = self.add_flags(entry, flags)
        return entry

    def parse_subrange_type(self, die, flags=None):
        """
        Parse a subrange type
        """
        entry = {"name": self.get_name(die)}
        entry.update(self.parse_underlying_type(die))

        # If we have DW_AT_count, this is the length of the subrange
        if "DW_AT_count" in die.attributes:
            entry["count"] = die.attributes["DW_AT_count"].value

        # If we have both upper and lower bound
        elif (
            "DW_AT_upper_bound" in die.attributes
            and "DW_AT_lower_bound" in die.attributes
        ):

            # TODO this looks like it can sometimes be a dwarf expression with a constant
            # see libpetsc.so
            try:
                entry["count"] = (
                    die.attributes["DW_AT_upper_bound"].value
                    - die.attributes["DW_AT_lower_bound"].value
                )
            except:
                pass

        # If the lower bound value is missing, the value is assumed to be a language-dependent default constant.
        elif "DW_AT_upper_bound" in die.attributes:

            # TODO need to get language in here to derive
            # TODO: size seems one off.
            # The default lower bound is 0 for C, C++, D, Java, Objective C, Objective C++, Python, and UPC.
            # The default lower bound is 1 for Ada, COBOL, Fortran, Modula-2, Pascal and PL/I.
            lower_bound = 0
            entry["count"] = die.attributes["DW_AT_upper_bound"].value - lower_bound

        # If the upper bound and count are missing, then the upper bound value is unknown.
        else:
            entry["count"] = "unknown"
        entry = self.add_flags(entry, flags)
        return entry

    def parse_class_type(self, die, flags=None):
        """
        Parse a class type
        """
        entry = {
            "name": self.get_name(die),
            "size": self.get_size(die),
            "class": "Class",
        }
        fields = []
        for child in die.iter_children():
            if not child.tag:
                continue
            if "DW_AT_external" in child.attributes:
                continue
            fields.append(self.parse_member(child))
        if fields:
            entry["fields"] = fields
        entry = self.add_flags(entry, flags)
        return entry

    def parse_imported_declaration(self, die, flags=None):
        """
        Parse an imported declaration.
        """
        if "DW_AT_import" in die.attributes:

            # This means we can't get the import
            try:
                imported = self.type_die_lookup[die.attributes["DW_AT_import"].value]
            except:
                return
            # DIE None case
            if not imported.tag:
                return
            if imported.tag == "DW_TAG_imported_declaration":
                return self.parse_imported_declaration(imported)
            if imported.tag == "DW_TAG_subprogram":
                return self.parse_subprogram(imported)
            elif imported.tag == "DW_TAG_member":
                return self.parse_member(imported)
            elif imported.tag in [
                "DW_TAG_enumerator",
                "DW_TAG_enum_type",
                "DW_TAG_enumeration_type",
            ]:
                return self.parse_enumeration_type(imported)
            elif imported.tag == "DW_TAG_typedef":
                return self.parse_typedef(imported)
            elif imported.tag in [
                "DW_TAG_formal_parameter",
                "DW_TAG_template_type_param",
            ]:
                return self.parse_formal_parameter(imported, allocator=None)
            elif imported.tag == "DW_TAG_class_type":
                return self.parse_class_type(imported)
            elif imported.tag == "DW_TAG_structure_type":
                return self.parse_structure_type(imported)
            # TODO: question - should this parse no matter what (e.g., skip external checks)
            # found in libsymtabAPI.so of dyninst
            elif imported.tag == "DW_TAG_variable":
                return self.parse_variable(imported)
            elif self.is_flag_type(imported):
                return self.parse_underlying_type(imported, flags=flags)

        # for development should be Ipython
        return self.parse_underlying_type(imported, flags=flags)

    def parse_typedef(self, die, flags=None):
        """
        Parse a type definition
        """
        entry = {"name": self.get_name(die)}
        underlying_type = self.parse_underlying_type(die)
        entry.update(underlying_type)
        entry = self.add_flags(entry, flags)
        return entry

    def is_flag_type(self, die):
        return die.tag in [
            "DW_TAG_const_type",
            "DW_TAG_constant",
            "DW_TAG_atomic_type",
            "DW_TAG_immutable_type",
            "DW_TAG_volatile_type",
            "DW_TAG_packed_type",
            "DW_TAG_shared_type",
            "DW_TAG_restrict_type",
        ]

    def update_flags(self, type_die, flags):
        """
        Given a type die, parse for flags to update.
        """
        # parse the underlying type, and add the appropriate flag
        if type_die.tag in ["DW_TAG_const_type", "DW_TAG_constant"]:
            flags.append("constant")
        if type_die.tag == "DW_TAG_atomic_type":
            flags.append("atomic")
        if type_die.tag == "DW_TAG_immutable_type":
            flags.append("immutable")
        if type_die.tag == "DW_TAG_volatile_type":
            flags.append("volatile")
        if type_die.tag == "DW_TAG_packed_type":
            flags.append("packed")
        if type_die.tag == "DW_TAG_shared_type":
            flags.append("shared")
        if type_die.tag == "DW_TAG_restrict_type":
            flags.append("restrict")
        return flags

    @cache_type
    def parse_underlying_type(
        self, die, allocator=None, flags=None, type_name="DW_AT_type"
    ):
        """
        Given a type, parse down to the underlying type
        """
        if "DW_AT_type" not in die.attributes:
            return {"type": "unknown"}

        # constant or volatile
        flags = flags or []

        # Can we get the underlying type?
        type_die = self.type_die_lookup.get(die.attributes[type_name].value)

        # Each of functions below can call this recursively
        # there was a formal parameter with a type as a compile unit in libgettext
        if (
            not type_die
            or not type_die.tag
            or type_die.tag
            in [
                "DW_TAG_compile_unit",
                "DW_TAG_unspecified_parameters",
                "DW_TAG_imported_module",
            ]
        ):
            return self.add_flags({"type": "unknown"}, flags)

        # Fortran common blocks are not types
        if type_die.tag == "DW_TAG_common_block":
            return self.add_flags({"type": "unknown"}, flags)

        # TODO: This packed type is likely incorrect - not sure how to parse
        if type_die.tag == "DW_TAG_GNU_formal_parameter_pack" and type_die.has_children:
            type_die = list(type_die.iter_children())[0]

        # A debugging information entry representing the type of an object that is a pointer18
        # to a structure or class member has the tag DW_TAG_ptr_to_member_type
        if type_die.tag == "DW_TAG_ptr_to_member_type":
            return self.parse_underlying_type(
                type_die, type_name="DW_AT_containing_type"
            )

        # subprogram -> type (return) is an import of a function
        if type_die.tag == "DW_TAG_imported_declaration":
            return self.parse_imported_declaration(type_die, flags=flags)

        if type_die.tag == "DW_TAG_pointer_type":
            return self.parse_pointer_type(type_die, parent=die, flags=flags)

        if type_die.tag == "DW_TAG_class_type":
            return self.parse_class_type(type_die, flags=flags)

        # formal param had type call site in libcurses.so
        if type_die.tag in ["DW_TAG_call_site", "DW_TAG_GNU_call_site"]:
            return self.parse_call_site(type_die, parent=die)

        # formal param had type call site param in libcrypto (libssl).so
        if type_die.tag in [
            "DW_TAG_call_site_parameter",
            "DW_TAG_GNU_call_site_parameter",
        ]:
            return self.parse_call_site_parameter(type_die)

        if type_die.tag == "DW_TAG_union_type":
            return self.parse_union_type(type_die, flags=flags)

        if type_die.tag in [
            "DW_TAG_enum_type",
            "DW_TAG_enumeration_type",
            "DW_TAG_enumerator",
        ]:
            return self.parse_enumeration_type(type_die, flags=flags)

        # Array (and type is for elements)
        if type_die.tag == "DW_TAG_array_type":
            return self.parse_array_type(type_die, parent=die, flags=flags)

        if type_die.tag == "DW_TAG_subprogram":
            return self.parse_subprogram(type_die)

        # Struct
        if type_die.tag == "DW_TAG_structure_type":
            return self.parse_structure_type(type_die, flags=flags)

        # A variable being used as a formal parameter? see bzip main so
        if type_die.tag == "DW_TAG_variable":
            return self.parse_variable(type_die, flags=flags)

        if type_die.tag == "DW_TAG_inlined_subroutine":
            return self.parse_inlined_subroutine(type_die)

        # See libcrypto.so for this case
        if type_die.tag == "DW_TAG_lexical_block":
            self.parse_lexical_block(type_die)
            return self.add_flags({"type": "unknown"}, flags)

        if type_die.tag == "DW_TAG_typedef":
            return self.parse_typedef(type_die, flags=flags)

        # DW_TAG None, we can't know
        if not type_die.tag:
            return self.add_flags({"type": "unknown"}, flags)

        # Note that if we see DW_TAG_member it means next_die for the DW_AT_type was empty
        if type_die.tag == "DW_TAG_class_type":
            return self.parse_class_type(type_die, flags=flags)

        # Additional flags based on the type die
        flags = self.update_flags(type_die, flags)

        if type_die.tag == "DW_TAG_base_type":
            return self.parse_base_type(type_die, flags=flags)

        # https://gcc.gnu.org/pipermail/fortran/2008-August/025359.html
        # in fortran this is like a char size 1
        if type_die.tag == "DW_TAG_string_type":
            return self.parse_string_type(type_die, flags=flags)

        # These are essentially skipped over to get to underlying type
        if self.is_flag_type(type_die) or type_die.tag in [
            "DW_TAG_formal_parameter",
            "DW_TAG_namespace",
            "DW_TAG_inheritance",
            "DW_TAG_member",
            "DW_TAG_reference_type",
            "DW_TAG_rvalue_reference_type",
            "DW_TAG_subrange_type",
            "DW_TAG_subroutine_type",
            "DW_TAG_template_type_param",
            "DW_TAG_unspecified_type",
            "DW_TAG_template_value_parameter",
            "DW_TAG_template_value_param",
            "DW_TAG_GNU_template_parameter_pack",
            "DW_TAG_GNU_formal_parameter_pack",
            "DW_TAG_label",
            "DW_TAG_module",
        ]:
            return self.parse_underlying_type(type_die, flags=flags)

        print(type_die)
        print("NOT SEEN TYPE DIE")
        sys.exit(0)

    def add_class(self, die):
        """
        Given a type, add the class
        """
        if die.tag == "DW_TAG_base_type":
            return ClassType.get(self.get_name(die))
        if die.tag == "DW_TAG_string_type":
            return "Integral"

        print("UNKNOWN DIE CLASS")
        return "Unknown"

    def get_size(self, die):
        """
        Return size in bytes (not bits)
        TODO is missing a size attribute == size 0 or unknown?
        """
        size = 0
        if "DW_AT_byte_size" in die.attributes:
            return die.attributes["DW_AT_byte_size"].value
        # A byte is 8 bits
        if "DW_AT_bit_size" in die.attributes:
            return die.attributes["DW_AT_bit_size"].value * 8
        if "DW_AT_data_bit_offset" in die.attributes:
            raise Exception("Found data_bit_offset in die to parse:\n%s" % die)
        return size

    def _find_nontraditional_size(self, die):
        """
        Tag DIEs can have attributes to indicate their members use a nontraditional
        amount of storage, in which case we find this. Otherwise, look at member size.
        """
        if "DW_AT_byte_stride" in die.attributes:
            return die.attributes["DW_AT_byte_stride"].value
        if "DW_AT_bit_stride" in die.attributes:
            return die.attributes["DW_AT_bit_stride"].value * 8

    def get_name(self, die):
        """
        A common function to get the name for a die
        """
        name = "unknown"
        if "DW_AT_linkage_name" in die.attributes:
            return bytes2str(die.attributes["DW_AT_linkage_name"].value)
        if "DW_AT_name" in die.attributes:
            return bytes2str(die.attributes["DW_AT_name"].value)
        return name
