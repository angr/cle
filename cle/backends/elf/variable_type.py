from __future__ import annotations

from enum import Enum

from elftools.dwarf.die import DIE

class VariableType:
    """
    Entry class for DW_TAG_xxx_type

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)

    :ivar name:             name of the type
    :type name:             str
    :ivar byte_size:        amount of bytes the type take in memory
    """

    def __init__(self, name: str, byte_size: int, elf_object):
        self.name = name
        self.byte_size = byte_size
        self._elf_object = elf_object

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        entry method to read a DW_TAG_xxx_type
        """
        if die.tag == "DW_TAG_base_type":
            return BaseType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_pointer_type":
            return PointerType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_structure_type":
            return StructType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_array_type":
            return ArrayType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_typedef":
            return TypedefType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_union_type":
            return UnionType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_enumeration_type":
            return EnumerationType.read_from_die(die, elf_object)
        elif die.tag == "DW_TAG_subroutine_type":
            return SubroutineType.read_from_die(die, elf_object)
        return None

    @staticmethod
    def supported_die(die: DIE) -> bool:
        return die.tag in (
            "DW_TAG_base_type",
            "DW_TAG_pointer_type",
            "DW_TAG_structure_type",
            "DW_TAG_array_type",
            "DW_TAG_typedef",
            "DW_TAG_union_type",
            "DW_TAG_enumeration_type",
            "DW_TAG_subroutine_type"
        )


class PointerType(VariableType):
    """
    Entry class for DW_TAG_pointer_type. It is inherited from VariableType

    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param referenced_offset:  type of the referenced as offset in the compilation_unit
    """

    def __init__(self, name: str | None, byte_size: int, elf_object, referenced_offset: int):
        if name is None:
            name = "pointer"
        super().__init__(name, byte_size, elf_object)
        self._referenced_offset = referenced_offset

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_pointer_type. return None when there is no
        byte_size or type attribute.
        """
        byte_size_attr = die.attributes.get("DW_AT_byte_size", None)

        name_attr = die.attributes.get("DW_AT_name", None)
        name = None if name_attr is None else name_attr.value.decode()

        if byte_size_attr is not None:
            byte_size = byte_size_attr.value
        else:
            # In testing it looks like the Rust compiler does not emit a byte_size attribute
            # Instead let's just say that the size of a pointer is given by the ELF's architecture
            byte_size = elf_object.arch.bytes

        dw_at_type = die.attributes.get("DW_AT_type", None)
        if dw_at_type is None:
            referenced_offset = None
        else:
            referenced_offset = dw_at_type.value + die.cu.cu_offset

        return cls(name, byte_size, elf_object, referenced_offset)

    @property
    def referenced_type(self):
        """
        attribute to get the referenced type. Return None if the type is not loaded
        """
        type_list = self._elf_object.type_list
        if self._referenced_offset in type_list.keys():
            return type_list[self._referenced_offset]
        return None

class BaseTypeEncoding(Enum):
    ADDRESS = 0x1
    BOOLEAN = 0x2
    COMPLEX_FLOAT = 0x3
    FLOAT = 0x4
    SIGNED = 0x5
    SIGNED_CHAR = 0x6
    UNSIGNED = 0x7
    UNSIGNED_CHAR = 0x8
    IMAGINARY_FLOAT = 0x9
    PACKED_DECIMAL = 0xa
    NUMERIC_STRING = 0xb
    EDITED = 0xc
    SIGNED_FIXED = 0xd
    UNSIGNED_FIXED = 0xe
    DECIMAL_FLOAT = 0xf
    UTF = 0x10
    UCS = 0x11
    ASCII = 0x12
    LO_USER = 0x80
    HI_USER = 0xff

class BaseType(VariableType):
    """
    Entry class for DW_TAG_base_type. It is inherited from VariableType
    """

    def __init__(self, name: str, byte_size: int, elf_object, encoding):
        super().__init__(name, byte_size, elf_object)
        self.encoding = encoding

    # for __init__ see VariableType

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_base_type. return None when there is no
        byte_size attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        byte_size = die.attributes.get("DW_AT_byte_size", None)
        encoding_attr = die.attributes.get("DW_AT_encoding", None)
        if encoding_attr is not None:
            encoding = BaseTypeEncoding(encoding_attr.value)
        else:
            encoding = None
        if byte_size is None:
            return None
        return cls(dw_at_name.value.decode() if dw_at_name is not None else "unknown", byte_size.value, elf_object, encoding)


class StructType(VariableType):
    """
    Entry class for DW_TAG_structure_type. It is inherited from VariableType

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    """

    def __init__(self, name: str, byte_size: int, elf_object, members):
        super().__init__(name, byte_size, elf_object)
        self.members = members

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_structure_type. return None when there is no
        byte_size attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        byte_size = die.attributes.get("DW_AT_byte_size", None)

        if byte_size is None:
            return None

        members = []
        for die_child in die.iter_children():
            if die_child.tag == "DW_TAG_member":
                members.append(StructMember.read_from_die(die_child, elf_object))

        return cls(
            dw_at_name.value.decode() if dw_at_name is not None else "unknown", byte_size.value, elf_object, members
        )

    def __getitem__(self, member_name):
        for member in self.members:
            if member.name == member_name:
                return member
        raise KeyError


class UnionType(StructType):
    """
    Entry class for DW_TAG_union_type. Inherits from StructType to make it trivial.
    """


class StructMember:
    """
    Entry class for DW_TAG_member. This is not a type but a named member inside a struct.
    Use the property `type` to get its variable type.

    :param name:            name of the member
    :param addr_offset:     address offset of the member in the struct
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param type_offset:     type as offset in the compilation_unit

    :ivar name:             name of the member
    """

    def __init__(self, name: str, addr_offset: int, type_offset, elf_object):
        self.name = name
        self.addr_offset = addr_offset
        self._elf_object = elf_object
        self._type_offset = type_offset

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_member_type. return None when there is no
        type attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        dw_at_type = die.attributes.get("DW_AT_type", None)
        dw_at_memloc = die.attributes.get("DW_AT_data_member_location", None)
        name = None if dw_at_name is None else dw_at_name.value.decode()
        ty = None if dw_at_type is None else dw_at_type.value + die.cu.cu_offset

        # From the DWARF5 manual, page 118:
        #    The member entry corresponding to a data member that is defined in a structure,
        #    union or class may have either a DW_AT_data_member_location attribute or a
        #    DW_AT_data_bit_offset attribute. If the beginning of the data member is the
        #    same as the beginning of the containing entity then neither attribute is required.
        # TODO bit_offset
        addr_offset = 0 if dw_at_memloc is None else dw_at_memloc.value

        return cls(name, addr_offset, ty, elf_object)

    @property
    def type(self):
        """
        attribute to get the type of the member. Return None if the type is not loaded
        """

        type_list = self._elf_object.type_list
        if self._type_offset in type_list.keys():
            return type_list[self._type_offset]
        return None


class ArrayType(VariableType):
    """
    Entry class for DW_TAG_array_type. It is inherited from VariableType

    :param byte_size:          amount of bytes the type take in memory
    :param elf_object:         elf object to reference to (useful for pointer,...)
    :param element_offset:     type of the array elements as offset in the compilation_unit
    """

    def __init__(self, byte_size, elf_object, element_offset, count: int | None, lower_bound: int | None, upper_bound: int | None):
        super().__init__("array", byte_size, elf_object)
        self._element_offset = element_offset
        self.count = count
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_array_type. return None when there is no
        type attribute.
        """

        dw_byte_size = die.attributes.get("DW_AT_byte_size", None)

        dw_at_type = die.attributes.get("DW_AT_type", None)
        if dw_at_type is None:
            return None

        count = None
        lower_bound = None
        upper_bound = None
        for child in die.iter_children():
            match child.tag:
                case "DW_TAG_subrange_type":
                    count_attr = child.attributes.get("DW_AT_count", None)
                    if count_attr is not None:
                        count = count_attr.value
                    lower_bound_attr = child.attributes.get("DW_AT_lower_bound", None)
                    if lower_bound_attr is not None:
                        lower_bound = lower_bound_attr.value
                    upper_bound_attr = child.attributes.get("DW_AT_upper_bound", None)
                    if upper_bound_attr is not None:
                        upper_bound = upper_bound_attr.value
                    break

        return cls(
            dw_byte_size.value if dw_byte_size is not None else None, elf_object, dw_at_type.value + die.cu.cu_offset,
            count, lower_bound, upper_bound
        )

    @property
    def element_type(self):
        type_list = self._elf_object.type_list
        if self._element_offset in type_list.keys():
            return type_list[self._element_offset]
        return None


class TypedefType(VariableType):
    """
    Entry class for DW_TAG_typedef. Inherits from VariableType.

    :param name:        name of the new type
    :param elf_object:  elf object to reference to (useful for pointer,...)
    :param type_offset: type as offset in the compilation_unit
    """

    def __init__(self, name: str, byte_size, elf_object, type_offset):
        super().__init__(name, byte_size, elf_object)
        self._type_offset = type_offset

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_member_type. return None when there is no
        type attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        dw_at_type = die.attributes.get("DW_AT_type", None)
        dw_at_byte_size = die.attributes.get("DW_AT_byte_size", None)
        name = None if dw_at_name is None else dw_at_name.value.decode()
        type_offset = None if dw_at_type is None else dw_at_type.value + die.cu.cu_offset
        byte_size = None if dw_at_byte_size is None else dw_at_byte_size.value

        return cls(name, byte_size, elf_object, type_offset)

    @property
    def type(self):
        """
        attribute to get the type of the member. Return None if the type is not loaded
        """

        type_list = self._elf_object.type_list
        if self._type_offset in type_list.keys():
            return type_list[self._type_offset]
        return None

class EnumeratorValue:
    def __init__(self, name: str, const_value):
        self.name = name
        self.const_value = const_value

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        name_attr = die.attributes.get("DW_AT_name", None)
        name = None if name_attr is None else name_attr.value.decode()

        const_value_attr = die.attributes.get("DW_AT_const_value", None)
        const_value = None if const_value_attr is None else const_value_attr.value

        return cls(name, const_value)

class EnumerationType(VariableType):
    def __init__(self, name: str, byte_size: int, elf_object, type_offset, enumerator_values: list[EnumeratorValue]):
        super().__init__(name, byte_size, elf_object)
        self.enumerator_values = enumerator_values
        self._type_offset = type_offset

    def __len__(self):
        return len(self.enumerator_values)

    def __iter__(self):
        return iter(self.enumerator_values)

    @property
    def type(self):
        """
        The underlying type of the enumeration
        """
        return self._elf_object.type_list[self._type_offset]

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_enumeration_type.
        """

        dw_byte_size = die.attributes.get("DW_AT_byte_size", None)
        byte_size = dw_byte_size.value if dw_byte_size is not None else None

        name_attr = die.attributes.get("DW_AT_name", None)
        name = None if name_attr is None else name_attr.value.decode()

        dw_at_type = die.attributes.get("DW_AT_type", None)
        type_offset = None if dw_at_type is None else dw_at_type.value + die.cu.cu_offset

        enumerators = []
        for child in die.iter_children():
            match child.tag:
                case "DW_TAG_enumerator":
                    enumerators.append(EnumeratorValue.read_from_die(child, elf_object))

        return cls(name, byte_size, elf_object, type_offset, enumerators)

class SubroutineType(VariableType):
    def __init__(self, name: str, byte_size: int, elf_object, type_offset: int | None, parameter_offsets):
        super().__init__(name, byte_size, elf_object)
        self._type_offset = type_offset
        self._parameter_offsets = parameter_offsets

    @property
    def type(self):
        """
        The return type of the subroutine, or None if the subroutine returns no value
        """
        if self._type_offset is None:
            return None
        else:
            return self._elf_object.type_list[self._type_offset]

    @property
    def parameters(self):
        """
        Iterates over the parameters of the subroutine
        """
        type_list = self._elf_object.type_list
        for offset in self._parameter_offsets:
            yield type_list[offset]

    @classmethod
    def read_from_die(cls, die: DIE, elf_object):
        """
        read an entry of DW_TAG_subroutine_type
        """

        dw_byte_size = die.attributes.get("DW_AT_byte_size", None)
        byte_size = dw_byte_size.value if dw_byte_size is not None else None

        name_attr = die.attributes.get("DW_AT_name", None)
        name = None if name_attr is None else name_attr.value.decode()

        dw_at_type = die.attributes.get("DW_AT_type", None)
        type_offset = None if dw_at_type is None else dw_at_type.value + die.cu.cu_offset

        parameter_offsets: list[int] = []
        for child in die.iter_children():
            match child.tag:
                case "DW_TAG_formal_parameter":
                    param_type_attr = child.attributes.get("DW_AT_type", None)
                    param_type_offset = None if param_type_attr is None else param_type_attr.value + die.cu.cu_offset
                    parameter_offsets.append(param_type_offset)

        return cls(name, byte_size, elf_object, type_offset, parameter_offsets)