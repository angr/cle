from elftools.common.py3compat import bytes2str
from elftools.dwarf.descriptions import describe_form_class, describe_reg_name
from elftools.dwarf.locationlists import LocationEntry, LocationExpr
from elftools.dwarf.dwarf_expr import DWARFExprParser, DW_OP_name2opcode

import cle.backends.elf.parser as abi_parser
from .location import get_register_from_expr, get_dwarf_from_expr
from .types import VariableType, ClassType
from ..corpus import Corpus

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
        self.arch = kwargs.get('arch')
        super().__init__(*args, **kwargs)
        self.seen = set()
        self.underlying_types = {}

        # Keep track of ids we have parsed before (underlying types)
        self.lookup = set()

    def parse_variable(self, die):
        """
        Add a global variable parsed from the dwarf.
        """
        # DW_AT_external attribute if the variable is visible outside of its enclosing CU
        if not "DW_AT_external" in die.attributes:
            return
        entry = {"name": self.get_name(die), "size": self.get_size(die)}
        entry.update(self.parse_underlying_type(die))
        self.variables.append(entry)

    def add_dwarf_information_entry(self, die):
        """
        Parse DIEs that aren't functions (subprograms) and variables.

        I started parsing recursively here, but I think each type function
        should handle parsing its own children.
        """   
        # And TODO variables
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

        if die.tag == "DW_TAG_variable":
            return self.parse_variable(die)
        if die.tag == "DW_TAG_subprogram":
            return self.parse_subprogram(die)

        if die.tag == "DW_TAG_union_type":
            return self.parse_union_type(die)

        if die.tag == "DW_TAG_enumeration_type":
            return self.parse_enumeration_type(die)

        if die.tag == "DW_TAG_array_type":
            return self.parse_array_type(die)

        if die.tag == "DW_TAG_structure_type":
            return self.parse_structure_type(die)

        if die.tag == "DW_TAG_lexical_block":
            return self.parse_die(die)

        if die.tag == "DW_TAG_member":
            return self.parse_member(die)

        if die.tag == "DW_TAG_base_type":
            return self.parse_base_type(die)

        # Legical blocks wrap other things
        if die.tag == "DW_TAG_lexical_block":
            return self.parse_children(die)

    def parse_children(self, die):
        for child in die.iter_children():
            self.parse_die(child)
             
    def parse_call_site(self, die, parent):
        """
        Parse a call site
        """
        entry = {}

        # The abstract origin points to the function
        if "DW_AT_abstract_origin" in die.attributes:
            origin = self.type_die_lookup.get(die.attributes['DW_AT_abstract_origin'].value)
            entry.update({"name": self.get_name(origin)})

        params = []
        for child in die.iter_children():
            # TODO need better param parsing
            if child.tag == "DW_TAG_GNU_call_site_parameter":
                param = self.parse_call_site_parameter(child)
                if param:
                    params.append(param)
            else:
                raise Exception("Unknown call site parameter!:\n%s" % child)

        if entry and params:
            entry['params'] = params
            self.callsites.append(entry)            

    def parse_call_site_parameter(self, die):
        """
        Given a callsite parameter, parse the dwarf expression
        """
        param = {}
        loc = self.parse_location(die)
        if loc:
            param['location'] = loc
        if "DW_AT_GNU_call_site_value" in die.attributes:
            expr_parser = DWARFExprParser(die.dwarfinfo.structs)
            expr = die.attributes['DW_AT_GNU_call_site_value'].value
            #print(get_dwarf_from_expr(expr, die.dwarfinfo.structs, cu_offset=die.cu.cu_offset))
        return param

    def parse_subprogram(self, die):
        """
        Add a function (subprogram) parsed from DWARF
 
        The design of this parser is assuming we want all things nested under
        functions, hence why we parse the subprogram children here to find
        the rest.
        """         
        # If has DW_TAG_external, we know it's external outside of this CU
        if "DW_AT_external" not in die.attributes:
            return

        # TODO see page 92 of https://dwarfstd.org/doc/DWARF4.pdf 
        # need to parse virtual functions and other attributesls
        entry = {"name": self.get_name(die)}

        return_value = None
        if "DW_AT_type" in die.attributes:       
            # TODO get register for this
            return_value = self.parse_underlying_type(die)
            return_value['location'] = "%" + describe_reg_name(0)
  
        params = []

        # Don't add die offsets we've seen before
        if die.offset in self.seen:
            return
        self.seen.add(die.offset)
 
        # Hold previous child for modifiers
        param = None

        for child in die.iter_children():
            
            # can either be inlined subroutine or format parameter
            if child.tag == "DW_TAG_formal_parameter":            
                loc = self.parse_location(child)
                param = {"name": self.get_name(child), "size": self.get_size(child)} 

                # Only add location if we know it!
                if loc:
                    param['location'] = loc
                param.update(self.parse_underlying_type(child))

            elif child.tag == "DW_TAG_inlined_subroutine":
                # If we have an abstract origin we know type for
                child = self.type_die_lookup.get(child.attributes["DW_AT_abstract_origin"].value)
                if child:
                    self.parse_subprogram(child)

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
                print('ARRAY')
                import IPython
                IPython.embed()
                param = self.parse_array_type(child)

            elif child.tag == "DW_TAG_structure_type":
                param = self.parse_structure_type(child)

            # Call sites
            elif child.tag in ["DW_TAG_GNU_call_site", "DW_TAG_call_site"]:
                param = self.parse_call_site(child, die)            

            # TODO is this only external stuff?
            elif child.tag == "DW_TAG_lexical_block": 
                self.parse_lexical_block(child)

            # Skip these
            elif child.tag in ["DW_TAG_const_type", "DW_TAG_typedef", "DW_TAG_label"]:
                continue
            else:
                raise Exception("Found new tag with subprogram children:\n%s" % child)
            if param:
                params.append(param)
                param = None
        if params:
            entry['parameters'] = params
        if return_value:
            entry['return'] = return_value
        self.functions.append(entry)

    # TAGs to parse
    def parse_lexical_block(self, die, code=None):
        """
        Lexical blocks typically have variable children?
        """
        for child in die.iter_children():
            if child.tag == "DW_TAG_variable":
                self.parse_variable(child)

            # We found a loop
            elif child.tag == "DW_AT_lexical_block":
                if code == die.abbrev_code:
                    return
                return self.parse_lexical_block(die)
        
    def parse_structure_type(self, die):
        """
        Parse a structure type.
        """
        # The size here includes padding
        entry = {"name": self.get_name(die), "size": self.get_size(die), "class": "Struct"}        
        fields = []
        for child in die.iter_children():
            fields.append(self.parse_member(child))
        if fields:
            entry['fields'] = fields
        self.underlying_types[die] = entry
        return entry

    def parse_base_type(self, die):
        """
        Parse a base type.
        """
        # The size here includes padding
        return {"type": self.get_name(die), "size": self.get_size(die), "class": "Scalar"}

    def parse_union_type(self, die):
        """
        Parse a union type.
        """
        # The size here includes padding
        entry = {"name": self.get_name(die), "size": self.get_size(die), "class": "Union"}
        
        # TODO An incomplete union won't have byte size attribute and will have DW_AT_declaration attribute.
        # page https://dwarfstd.org/doc/DWARF4.pdf 85

        # Parse children (members of the union)
        fields = []
        for child in die.iter_children():
            fields.append(self.parse_member(child))

        if fields:
            entry['fields'] = fields
        return entry

    def parse_location(self, die):
        """
        Look to see if the DIE has DW_AT_location, and if so, parse to get
        registers. The loc_parser is called by elf.py (once) and addde
        to the corpus here when it is parsing DIEs.
        """
        # Envar to control (force) using dwarf locations
        experimental_parsing = os.environ.get('CLE_ELF_EXPERIMENTAL_PARSING') is not None        

        # Can we parse based on an underlying type and arch?
        if experimental_parsing:
            parser = getattr(abi_parser, self.arch.name, None)
            if not parser:
                sys.exit("Experimental parsing selected by ABI for %s is not supported yet." % self.arch.name)            
            if die.tag == "DW_AT_structure_type":
                print('FOO')
                import IPython
                IPython.embed()
            underlying_type = self.parse_underlying_type(die)
            if underlying_type:
                loc = parser.classify(underlying_type, die=die)
                if loc:
                    return loc
            import IPython
            IPython.embed()
            sys.exit()

        # Fallback to using dwarf location lists
        return self.parse_dwarf_location(die)

    def parse_dwarf_location(self, die):
        """
        Get location information from dwarf location lists
        """
        if "DW_AT_location" not in die.attributes:
            return
        attr = die.attributes["DW_AT_location"]
        if self.loc_parser.attribute_has_location(attr, die.cu['version']):
             loc = self.loc_parser.parse_from_attribute(attr, die.cu['version'])

             # Attribute itself contains location information
             if isinstance(loc, LocationExpr):
                 loc = get_register_from_expr(loc.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset)
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
            return "framebase" + register.split(':')[-1].strip()
        # If we have a ( ) this is the register name
        if re.search(r'\((.*?)\)',register):
            return "%" + re.sub("(\(|\))", "", re.search(r"\((.*?)\)", register).group(0))
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
                registers.append(get_register_from_expr(loc_entity.loc_expr, die.dwarfinfo.structs, die.cu.cu_offset))
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

    def parse_array_type(self, die):
        """
        Get an entry for an array.
        """
        # TODO what should I do if there is DW_AT_sibling? Use it for something instead?
        entry = {"class": "Array", "name": self.get_name(die)}

        # Get the type of the members
        member_type = self.parse_underlying_type(die)       

        # TODO we might want to handle order
        # This can be DW_AT_col_order or DW_AT_row_order, and if not present
        # We use the language default
        if "DW_AT_ordering" in die.attributes:
            entry['order'] = die.attributes['DW_AT_ordering'].value

        # Case 1: the each member of the array uses a non-traditional storage
        member_size = self._find_nontraditional_size(die)
                
        # Children are the members of the array
        entries = []        
        children = list(die.iter_children())

        size = 0
        total_size = 0
        total_count = 0
        for child in children:
            member = None

            # Each array dimension is DW_TAG_subrange_type or DW_TAG_enumeration_type
            if child.tag == "DW_TAG_subrange_type":
                member = self.parse_subrange_type(child)
            elif child.tag == "DW_TAG_enumeration_type":
                member = self.parse_enumeration_type(child)
            else:
                l.warning('Unknown array member tag %s' % child.tag)

            if not member:
                continue

            count = member.get('count', 0)
            size = member.get('size') or member_size
            if count != "unknown" and size:
                total_size += (count * size)
            entries.append(member)

        entry['size'] = total_size
        entry['count'] = total_count
        return entry

    def parse_enumeration_type(self, die):
        entry = {"name": self.get_name(die), "size": self.get_size(die), "class": "Scalar"}
        underlying_type = self.parse_underlying_type(die)
        entry.update(underlying_type)

        fields = []
        for child in die.iter_children():
            field = {"name": self.get_name(child), "value": child.attributes['DW_AT_const_value'].value}
            fields.append(field)
        if fields:
            entry['fields'] = fields
        return entry
 
    def parse_subrange_type(self, die):
        """
        Parse a subrange type
        """       
        entry = {"name": self.get_name(die)}
        entry.update(self.parse_underlying_type(die))

        # If we have DW_AT_count, this is the length of the subrange        
        if "DW_AT_count" in die.attributes:
            entry['count'] = die.attributes['DW_AT_count'].value
        
        # If we have both upper and lower bound            
        elif "DW_AT_upper_bound" in die.attributes and "DW_AT_lower_bound" in die.attributes:
            entry['count'] = die.attributes['DW_AT_upper_bound'].value - die.attributes['DW_AT_lower_bound'].value

        # If the lower bound value is missing, the value is assumed to be a language-dependent default constant.
        elif "DW_AT_upper_bound" in die.attributes:

            # TODO need to get language in here to derive
            # TODO: size seems one off.
            # The default lower bound is 0 for C, C++, D, Java, Objective C, Objective C++, Python, and UPC. 
            # The default lower bound is 1 for Ada, COBOL, Fortran, Modula-2, Pascal and PL/I.
            lower_bound = 0
            entry['count'] = die.attributes['DW_AT_upper_bound'].value - lower_bound

        # If the upper bound and count are missing, then the upper bound value is unknown. 
        else:
            entry['count'] = "unknown"
        return entry

    def parse_pointer(self, die):
        """
        Parse a pointer.
        """
        if "DW_AT_type" not in die.attributes:
            l.debug("Cannot parse pointer %s without a type." % die)
            return
  
        entry = {"class": "Pointer", "size": self.get_size(die)}
            
        # We already have one pointer indirection
        entry['underlying_type'] = self.parse_underlying_type(die, 1)
        return entry

    def parse_sibling(self, die):
        """
        Try parsing a sibling.
        """
        sibling = self.type_die_lookup.get(die.attributes["DW_AT_sibling"].value)
        return self.parse_underlying_type(sibling)

    def parse_underlying_type(self, die, indirections=0):
        """
        Given a type, parse down to the underlying type (and count pointer indirections)
        """       
        if die in self.underlying_types:
            return self.underlying_types[die]

        entry = {}
        if "DW_AT_type" not in die.attributes:
            return entry
        
        # Can we get the underlying type?
        type_die = self.type_die_lookup.get(die.attributes["DW_AT_type"].value)

        # TODO need another function to parse types but not call get_underlying_type?
        if not type_die:
            return {"type": "unknown"}

        # Case 1: It's an array (and type is for elements)
        if type_die and type_die.tag == "DW_TAG_array_type":
            entry = self.parse_array_type(type_die)
            array_type = self.parse_underlying_type(type_die)
            entry.update({"name": self.get_name(die), "class": "Array", "type": array_type['type']})
            return entry

        # Struct
        elif type_die and type_die.tag == "DW_TAG_structure_type":
            return self.parse_structure_type(type_die)

        # Otherwise, keep digging
        elif type_die:
            while "DW_AT_type" in type_die.attributes:

                # Having indirections means we have a pointer somewhere
                if type_die.tag == "DW_TAG_pointer_type":
                    indirections +=1
                next_die = self.type_die_lookup.get(type_die.attributes["DW_AT_type"].value)
                if not next_die:
                    break
                type_die = next_die


            # Parse the underlying bits
            # TODO need to sometimes parse deeper but not go recursive...
            entry = {"type": self.get_name(type_die), "size": self.get_size(type_die)}
            #updated = self.parse_die(type_die)
            #entry.update(updated)

            if type_die and type_die.tag == "DW_AT_structure_type":
                entry = self.parse_structure_type(type_die)

            # Only add non zero indirections
            if indirections != 0:
                entry['indirections'] = indirections

        # Based on the underlying type, add a class
        entry['class'] = self.add_class(type_die)
        return entry

    def add_class(self, die):
        """
        Given a type, add the class
        """
        if die.tag == "DW_TAG_base_type":
            return ClassType.get(self.get_name(die))
        if die.tag == "DW_TAG_structure_type":
            return "Struct"
        if die.tag == "DW_TAG_array_type":
            return "Array"
        return "Unknown"

    def get_size(self, die):
        """
        Return size in bytes (not bits)
        TODO is missing a size attribute == size 0 or unknown?
        """
        size = 0
        if "DW_AT_byte_size" in die.attributes:
            return die.attributes['DW_AT_byte_size'].value
        # A byte is 8 bits
        if "DW_AT_bit_size" in die.attributes:
            return die.attributes['DW_AT_bit_size'].value * 8
        if "DW_AT_data_bit_offset" in die.attributes:
            raise Exception("Found data_bit_offset in die to parse:\n%s" % die)
        return size

    def _find_nontraditional_size(self, die):
        """
        Tag DIEs can have attributes to indicate their members use a nontraditional
        amount of storage, in which case we find this. Otherwise, look at member size.
        """
        if "DW_AT_byte_stride" in die.attributes:
            return die.attributes['DW_AT_byte_stride'].value
        if "DW_AT_bit_stride" in die.attributes:
            return die.attributes['DW_AT_bit_stride'].value * 8


    def get_name(self, die):
        """
        A common function to get the name for a die
        """
        name = "unknown"
        if "DW_AT_linkage_name"  in die.attributes:
            return bytes2str(die.attributes['DW_AT_linkage_name'].value)
        if "DW_AT_name" in die.attributes:
            return bytes2str(die.attributes['DW_AT_name'].value)
        return name
