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
import hashlib
import json
import logging
import sys
import copy

l = logging.getLogger(name=__name__)
unknown_type = {"type": "unknown", "class": "Unknown"}


def create_location_lookup(res):
    """
    Create a helper location lookup to match registers based on param types
    """
    # Create a "best effort" lookup of type ids
    lookup = {}
    if not res.regclass:
        return lookup
    for eb in res.regclass:
        for field in eb.fields:
            if "location" not in field or "type_uid" not in field:
                continue
            if field["type_uid"] in lookup:
                lookup[field["type_uid"]].append(field["location"])
            else:
                lookup[field["type_uid"]] = [field["location"]]
    return lookup


def add_direction(param, types, is_struct=False):
    """
    Add direction to a normal parameter
    """
    is_pointer = param.get("class") == "Pointer"

    # Look for pointers as far as we can go
    if not is_pointer:
        holder = param
        while "type" in holder and len(holder["type"]) == 32:
            holder = types[holder["type"]]
            if holder.get("class") == "Pointer":
                is_pointer = True
                break
            while "underlying_type" in holder:
                holder = holder["underlying_type"]

    if is_pointer:
        param["direction"] = "both"
    else:
        param["direction"] = "import"
    return param


def update_underlying_type(param, types, lookup=None, underlying_type=None):
    """
    Given some kind of underlying type, match fields to locations.
    """
    underlying_type = underlying_type or copy.deepcopy(types[param["type"]])

    # Our default is import but Matt wants struct param fields to be exports
    direction = "import"
    if underlying_type.get("class") == "Struct":
        direction = "export"

    for field in underlying_type.get("fields", []):
        field_type = field.get("type")
        if lookup and field_type in lookup and lookup[field_type]:
            field["location"] = lookup[field_type].pop(0)
            if field.get("class") == "Pointer":
                field["direction"] = "both"
            else:
                field["direction"] = direction

        # We have to unwrap the type again
        elif lookup and field_type and field_type in types:
            ut = copy.deepcopy(types[field_type])
            field["type"] = update_underlying_type(
                ut,
                types=types,
                underlying_type=ut,
                lookup=lookup,
            )
    return underlying_type


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
        self.include_private = kwargs.get("include_private", True)
        super().__init__(*args, **kwargs)

        # self.types is cache of type id -> json
        # Types cache of die.offset -> type id
        self._types = {}
        self._types_seen = set()

        # Keep track of ids we have parsed before (underlying types)
        self.lookup = set()

    def add_locations(self):
        """
        Add locations is a post processing step to add locations for each function
        """
        for _, var in self.variables.items():
            if "type" not in var:
                continue
            underlying_type = copy.deepcopy(self.types[var["type"]])
            if underlying_type.get("class") == "Struct":
                for field in underlying_type.get("fields", []):
                    field["direction"] = var.get("direction", "export")
                var["type"] = underlying_type

        for func in self.functions:

            # Add function direction?
            if func.get("name") in self.symbols:
                func["direction"] = self.symbols[func.get("name")]

            # Set the allocator on the level of the function
            self.add_function_locations(func)

            if "return" in func:
                return_allocator = self.parser.get_return_allocator()
                loc = self.parse_location(func["return"], return_allocator)

                # Return is always an export
                func["return"]["direction"] = "export"
                if not loc:
                    continue

                # If we get an aggregate, it's really a pointer to it
                if not isinstance(
                    loc.regclass, self.parser.register_class.RegisterClass
                ):
                    func["return"]["location"] = return_allocator.get_register_string(
                        reg=self.parser.register_class.RegisterClass.INTEGER, size=8
                    )
                    continue

                # Otherwise we got a register class
                if loc and loc.regclass:
                    func["return"]["location"] = return_allocator.get_register_string(
                        reg=loc.regclass, size=func["return"].get("size", 0)
                    )

    def get_function_pointer(self, param, func, order):
        """
        Parse a parameter (json) to determine if a function pointer.
        """
        if "type" not in param or len(param["type"]) != 32:
            return

        # This might not be true, we check with underlying type
        pointer_type = self.types[param["type"]]
        if "underlying_type" not in pointer_type:
            return
        underlying_type = pointer_type["underlying_type"].get("type")
        if not underlying_type or underlying_type not in self.types:
            return
        underlying_type = self.types[underlying_type]
        if underlying_type.get("class") == "Function":
            name = func.get("name", "unknown") + "_func_pointer_" + str(order)
            if underlying_type.get("name") != "unknown":
                name += "_" + underlying_type.get("name")
            underlying_type["name"] = name
            return copy.deepcopy(underlying_type)

    def add_function_locations(self, func):
        """
        Add locations to a function (recursively)
        This is where we create the allocator to respond to the classifications.
        """
        allocator = self.parser.get_allocator()
        for order, param in enumerate(func.get("parameters", [])):
            res = self.parse_location(param, allocator)
            if not res:
                continue

            # We hit a pointer and were givn a string
            if isinstance(res, str):
                param["location"] = res
                continue

            # We are given a class directly by the classifier
            is_aggregate = False
            if isinstance(res.regclass, self.parser.register_class.RegisterClass):

                size = param.get("size", 0)
                if param.get("type") in self.types:
                    size = self.types[param.get("type")].get("size") or 0
                param["location"] = allocator.get_register_string(
                    reg=res.regclass, size=size
                )

            # We had an aggregate!
            else:
                allocator.start_transaction()
                is_aggregate = True

                do_rollback = False
                has_register = False
                for eb in res.regclass:
                    loc = allocator.get_register_string(reg=eb.regclass, size=8)

                    # Workaround for if we return None in above
                    if not loc:
                        continue

                    # We've seen registers but now we see a stack location, ohno rollback
                    if has_register and "framebase" in loc:
                        do_rollback = True
                        break

                    # We've seen (allocated) a register
                    if "framebase" not in loc:
                        has_register = True
                    for field in eb.fields:
                        field["location"] = loc

                if do_rollback:
                    allocator.rollback()
                    for eb in res.regclass:
                        loc = allocator.fallocator.next_framebase_from_type(size=8)
                        for field in eb.fields:
                            field["location"] = loc

                # Clear any saved state for rolling back aggregates
                allocator.end_transaction()

            # Check if param type is pointer -> function
            func_pointer = self.get_function_pointer(param, func, order)
            if func_pointer:
                self.functions.append(func_pointer)
                self.add_function_locations(func_pointer)

            # Pointers go in both directions
            param = add_direction(param, types=self.types)

            # A non-aggregate
            if not is_aggregate:
                continue

            lookup = create_location_lookup(res)

            # Res is a classification with eighbytes we unwrap
            # Try just unwrapping the top level for now
            param["type"] = update_underlying_type(
                param, lookup=lookup, types=self.types
            )

    def hash(self, typ):
        """
        Generate a unique hash depending on the type
        """
        dumped = json.dumps(typ, sort_keys=True)
        return hashlib.md5(dumped.encode("utf-8")).hexdigest()

    def parse_location(self, entry, allocator):
        """
        Look to see if the DIE has DW_AT_location, and if so, parse to get
        registers. The loc_parser is called by elf.py (once) and addde
        to the corpus here when it is parsing DIEs.
        """
        # Pointer gets next integer register
        if entry.get("class") == "Pointer":
            return allocator.get_next_int_register()

        if not self.parser:
            sys.exit(
                "Experimental parsing selected by ABI for %s is not supported yet."
                % self.arch.name
            )

        underlying_type = self.types.get(entry.get("type"))
        if not underlying_type:
            return
        return self.parser.classify(underlying_type, types=self.types)

    def parse_variable(self, die, flags=None):
        """
        Add a global variable parsed from the dwarf.

        Since we need to parse the DIE for the direction, we parse directions
        here with variables.
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

        # Add underlying type
        entry.update(self.parse_underlying_type(die))

        # Stop parsing if we've seen it before
        if entry["name"] in self.variables:
            return

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
                return unknown_type
        return unknown_type

    def parse_call_site_parameter(self, die):
        """
        Given a callsite parameter, parse the dwarf expression
        """
        param = {}
        loc = self.parse_dwarf_location(die)
        if loc:
            param["location"] = loc
        return param

        # param = self.parse_location(param, die)

        # Most callsite params just have a location and value
        # if "location" not in param or not param['location']:

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

    def parse_reference_type(self, die, flags=None):
        """
        Parse a reference type
        """
        size = self.get_size(die)
        entry = {"class": "Reference"}
        if size:
            entry["size"] = size
        entry["underlying_type"] = self.parse_underlying_type(die)
        return self.add_flags(entry, flags)

    def parse_pointer_type(self, die, parent, flags=None):
        """
        This is hit parsing a pointer function param

        The parent (from the type) will have the name
        """
        parent = parent or die

        # Use the parent for name or the die
        name = self.get_name(parent)
        if name == "unknown":
            name = self.get_name(die)

        # Get the underlying type - if unknown we consider void
        # This is a void pointer / pointer to void
        ut = self.parse_underlying_type(die)["type"]
        underlying_type = self.parse_underlying_type(die)
        if ut in self.types:
            ut = self.types[ut]
            if ut.get("type") == "unknown":
                ut = {"type": "void", "class": "Void"}
                uid = self.hash(ut)
                self.types[uid] = ut
                underlying_type = {"type": uid}

        entry = {
            "class": "Pointer",
            "size": self.get_size(die),
            "underlying_type": underlying_type,
        }
        if name != "unknown":
            entry["name"] = name
        return self.add_flags(entry, flags)

    def parse_formal_parameter(self, die, flags=None):
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
        return self.add_flags(entry, flags)

    def parse_subprogram(self, die, flags=None):
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
        # But this doesn't seem to be relevant if we pass a DW_TAG_subroutine here
        if die.tag == "DW_TAG_subprogram" and "DW_AT_external" not in die.attributes:
            return

        # TODO see page 92 of https://dwarfstd.org/doc/DWARF4.pdf
        # need to parse virtual functions and other attributes
        entry = {"name": name, "class": "Function"}

        # Parse the return value
        return_value = None
        if "DW_AT_type" in die.attributes:
            return_value = self.parse_underlying_type(die)
        else:
            return_value = {
                "location": "none",
                "type": "void",
                "class": "Void",
            }

        params = []

        # Hold previous child for modifiers
        param = None
        for child in die.iter_children():

            if not child.tag:
                continue

            # can either be inlined subroutine or format parameter
            if child.tag in ["DW_TAG_formal_parameter", "DW_TAG_template_value_param"]:
                param = self.parse_formal_parameter(child)

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
                param = self.parse_structure_type(child, flags=flags)
            elif child.tag == "DW_TAG_pointer_type":
                param = self.parse_pointer_type(child, parent=die, flags=flags)
            elif child.tag == "DW_TAG_imported_declaration":
                param = self.parse_imported_declaration(child, flags=flags)
            elif child.tag == "DW_TAG_subprogram":
                param = self.parse_subprogram(child, flags=flags)
            elif child.tag == "DW_TAG_reference_type":
                param = self.parse_reference_type(child, flags=flags)
            elif child.tag == "DW_TAG_subroutine_type":
                param = self.parse_subprogram(child, flags=flags)

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
                    "DW_TAG_common_block",
                ]
                or not child.tag
            ):
                continue

            else:
                continue
            if param:
                params.append(param)
            param = None
        if params:
            entry["parameters"] = params
        if return_value:
            entry["return"] = return_value

        self.functions.append(entry)
        return copy.deepcopy(self.add_flags(entry, flags))

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
        has_inheritance = False
        for child in die.iter_children():

            # DIE None
            if not child.tag:
                continue

            # An inheritance tag is added as a pointer
            if child.tag == "DW_TAG_inheritance":
                has_inheritance = True
                field = self.parse_member(child)

                # Call the field name "inherited" to indicate that
                if field.get("name") in ["unknown", None]:
                    field["name"] = "inherited"
            else:
                field = self.parse_member(child)
            fields.append(field)

        if fields:
            entry["fields"] = fields

        if has_inheritance:
            entry = {
                "class": "Pointer",
                "size": 8,  # We are ignoring 32 bit
                "underlying_type": entry,
            }
        return self.add_flags(entry, flags)

    def parse_string_type(self, die, flags=None):
        """
        In Fortran the char size 1 is presented as a string
        """
        # The size here includes padding
        entry = {
            "type": "char",
            "size": self.get_size(die),
            "class": self.add_class(die),
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
        }
        # __int128 is treated as struct{long,long};
        if entry["type"] == "__int128":

            # TODO How do we differentiate between __int128 and __m128i?
            long_type = {"class": "Integer", "type": "long", "size": 8}
            uid = self.hash(long_type)
            self.types[uid] = long_type
            struct = {
                "size": 16,
                "class": "Struct",
                "fields": [
                    {"name": "__int128_1", "type": uid, "offset": 0},
                    {"name": "__int128_2", "type": uid, "offset": 8},
                ],
            }
            uid = self.hash(struct)
            self.types[uid] = struct
            struct = self.add_flags(struct, flags)
            return struct

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
        # Add the DW_AT_data_member_location (offset?)
        return self.add_offset(die, entry)

    def add_offset(self, die, entry):
        """
        Shared function to add offset based on DW_AT_data_member_location.
        This can be used for a struct member or an inheritanc tags.
        """
        if "DW_AT_data_member_location" in die.attributes:
            entry["offset"] = die.attributes["DW_AT_data_member_location"].value
        return entry

    def parse_array_type(self, die, parent=None, flags=None):
        """
        Get an entry for an array.
        """
        parent = parent or die

        # TODO what should I do if there is DW_AT_sibling? Use it for something instead?
        entry = {"class": "Array", "name": self.get_name(die)}

        # Get the type of the members
        array_type = self.parse_underlying_type(die, return_type=True)
        size = array_type.get("size", 0)

        # TODO we might want to handle order
        # This can be DW_AT_col_order or DW_AT_row_order, and if not present
        # We use the language default
        if "DW_AT_ordering" in die.attributes:
            entry["order"] = die.attributes["DW_AT_ordering"].value

        # Case 1: the each member of the array uses a non-traditional storage
        member_size = self._find_nontraditional_size(die) or size

        # Children are the members of the array
        children = list(die.iter_children())

        total_size = 0
        total_count = 0
        member_counts = []
        for child in children:
            if not child.tag:
                continue
            member = None

            # Each array dimension is DW_TAG_subrange_type or DW_TAG_enumeration_type
            # NOTE member type here is type of the INDEX
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
            if count not in ["unknown", 0] and not total_count:
                total_count = count
            elif count not in ["unknown", 0]:
                total_count = total_count * count
            if count not in ["unknown", 0]:
                member_counts.append(count)

        entry["size"] = total_count * member_size
        entry["counts"] = member_counts

        # Update info with the parent
        entry.update(
            {
                "name": self.get_name(parent),
                "class": "Array",
            }
        )

        entry = self.add_flags(entry, flags)
        entry["underlying_type"] = array_type
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
                ) + 1
            except:
                pass

        # If the lower bound value is missing, the value is assumed to be a language-dependent default constant.
        elif "DW_AT_upper_bound" in die.attributes:

            # TODO need to get language in here to derive
            # TODO: size seems one off.
            # The default lower bound is 0 for C, C++, D, Java, Objective C, Objective C++, Python, and UPC.
            # The default lower bound is 1 for Ada, COBOL, Fortran, Modula-2, Pascal and PL/I.
            lower_bound = 0

            # fortrilinos-2.0.0-egurmfvolea7xwcw3w3t6wkeus5iz64j/lib64/libforteuchos.so...
            try:
                entry["count"] = (
                    die.attributes["DW_AT_upper_bound"].value - lower_bound
                ) + 1
            except:
                pass

        # If the upper bound and count are missing, then the upper bound value is unknown.
        if "count" not in entry:
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
                return self.parse_formal_parameter(imported)
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
        return self.parse_underlying_type(imported, flags=flags)

    def parse_typedef(self, die, flags=None):
        """
        Parse a type definition
        """
        entry = {"name": self.get_name(die), "class": "TypeDef"}
        ut = self.parse_underlying_type(die)

        # Add the size to the typedef (shouldn't change)
        while "size" not in ut and "type" in ut and len(ut["type"]) == 32:
            ut = self.types[ut["type"]]

        entry["underlying_type"] = ut
        entry["size"] = ut.get("size")

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
    def parse_underlying_type(self, die, flags=None, type_name="DW_AT_type"):
        """
        Given a type, parse down to the underlying type
        """
        if "DW_AT_type" not in die.attributes:
            return unknown_type

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
            return self.add_flags(unknown_type, flags)

        # Fortran common blocks are not types
        if type_die.tag == "DW_TAG_common_block":
            return self.add_flags(unknown_type, flags)

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

        if type_die.tag == "DW_TAG_reference_type":
            return self.parse_reference_type(type_die, flags=flags)

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
            return self.parse_subprogram(type_die, flags=flags)

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
            return self.add_flags(unknown_type, flags)

        if type_die.tag == "DW_TAG_typedef":
            return self.parse_typedef(type_die, flags=flags)

        # DW_TAG None, we can't know
        if not type_die.tag:
            return self.add_flags(unknown_type, flags)

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

        # A subroutine type is...
        if type_die.tag == "DW_TAG_subroutine_type":
            return self.parse_subprogram(type_die, flags=flags)

        # These are essentially skipped over to get to underlying type
        if self.is_flag_type(type_die) or type_die.tag in [
            "DW_TAG_formal_parameter",
            "DW_TAG_namespace",
            "DW_TAG_inheritance",
            "DW_TAG_member",
            "DW_TAG_reference_type",
            "DW_TAG_rvalue_reference_type",
            "DW_TAG_subrange_type",
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
