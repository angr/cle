from elftools.dwarf.die import DIE


class VariableType:
    """
    Entry class for DWARF_TAG_..._type

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
        entry method to read a DW_TAG_..._type
        """
        if die.tag == 'DW_TAG_base_type':
            return BaseType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_pointer_type':
            return PointerType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_structure_type':
            return StructType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_member':
            return MemberType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType.read_from_die(die, elf_object)
        return None

    @staticmethod
    def supported_die(die: DIE) -> bool:
        return die.tag == 'DW_TAG_base_type'\
            or die.tag == 'DW_TAG_pointer_type'\
            or die.tag == 'DW_TAG_structure_type'\
            or die.tag == 'DW_TAG_member'\
            or die.tag == 'DW_TAG_array_type'


class PointerType(VariableType):
    """
    Entry class for DWARF_TAG_pointer_type. It is inherited from VariableType

    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param referenced_offset:  type of the referenced as offset in the compilation_unit
    """

    def __init__(self, byte_size: int, elf_object, referenced_offset: int):
        super().__init__('pointer', byte_size, elf_object)
        self._referenced_offset = referenced_offset

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        read an entry of DW_TAG_pointer_type. return None when there is no
        byte_size or type attribute.
        """
        byte_size = die.attributes.get('DW_AT_byte_size', None)

        if byte_size is None:
            return None

        dw_at_type = die.attributes.get('DW_AT_type', None)
        if dw_at_type is None:
            return None

        return PointerType(byte_size.value, elf_object, dw_at_type.value)

    @property
    def referenced_type(self):
        """
        attribute to get the referenced type. Return None if the type is not loaded
        """
        type_list = self._elf_object.type_list
        if self._referenced_offset in type_list.keys():
            return type_list[self._referenced_offset]
        return None


class BaseType(VariableType):
    """
    Entry class for DWARF_TAG_base_type. It is inherited from VariableType
    """

    def __init__(self, name: str, byte_size: int, elf_object):
        super().__init__(name, byte_size, elf_object)

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        read an entry of DW_TAG_base_type. return None when there is no
        byte_size attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        byte_size = die.attributes.get("DW_AT_byte_size", None)
        if byte_size is None:
            return None
        return BaseType(
            dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size.value,
            elf_object
        )


class StructType(VariableType):
    """
    Entry class for DWARF_TAG_structure_type. It is inherited from VariableType

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param member_offsets:  all structure member types as offsets in the compilation_unit
    """

    def __init__(self, name: str, byte_size: int, elf_object, member_offsets):
        super().__init__(name, byte_size, elf_object)
        self._member_offsets = member_offsets

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        read an entry of DW_TAG_structure_type. return None when there is no
        byte_size attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        byte_size = die.attributes.get('DW_AT_byte_size', None)

        if byte_size is None:
            return None

        member_offsets = []
        for die_children in die.iter_children():
            if VariableType.supported_die(die_children):
                member_offset = die_children.offset
                member_offsets.append(member_offset)

        return StructType(
            dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size.value,
            elf_object,
            member_offsets
        )

    @property
    def member_types(self):
        """
        attribute to get a list of all members type.
        Member entry is loaded correspond to the order defined in source code
        Member could be None if the type is not loaded (not supported)
        """
        members = []
        type_list = self._elf_object.type_list
        for member_offset in self._member_offsets:
            if member_offset in type_list.keys():
                members.append(type_list[member_offset].type)
            else:
                members.append(None)
        return members


class MemberType:
    """
    Entry class for DWARF_TAG_member_type.
    Note that this is not a real type, it is just a named member inside a stuct or union.
    Use the property `type` of a member to get the proper variable type.

    :param name:          name of the member
    :param elf_object:    elf object to reference to (useful for pointer,...)
    :param type_offset:   type as offset in the compilation_unit

    :ivar name:           name of the member
    """

    def __init__(self, name: str, elf_object, type_offset):
        self.name = name
        self._elf_object = elf_object
        self._type_offset = type_offset

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        read an entry of DW_TAG_member_type. return None when there is no
        type attribute.
        """

        dw_at_name = die.attributes.get('DW_AT_name', None)

        dw_at_type = die.attributes.get('DW_AT_type', None)
        if dw_at_type is None:
            return None
        return MemberType(
            dw_at_name.value.decode() if dw_at_name is not None else 'unknown',
            elf_object,
            dw_at_type.value
        )

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
    Entry class for DWARF_TAG_array_type. It is inherited from VariableType

    :param byte_size:          amount of bytes the type take in memory
    :param elf_object:         elf object to reference to (useful for pointer,...)
    :param element_offset:     type of the array elements as offset in the compilation_unit
    """

    def __init__(self, byte_size, elf_object, element_offset):
        super().__init__('array', byte_size, elf_object)
        self._element_offset = element_offset

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        read an entry of DW_TAG_array_type. return None when there is no
        type attribute.
        """

        dw_byte_size = die.attributes.get("DW_AT_byte_size", None)

        dw_at_type = die.attributes.get("DW_AT_type", None)
        if dw_at_type is None:
            return None
        return ArrayType(
            dw_byte_size.value if dw_byte_size is not None else None,
            elf_object,
            dw_at_type.value
        )

    @property
    def element_type(self):
        type_list = self._elf_object.type_list
        if self._element_offset in type_list.keys():
            return type_list[self._element_offset]
        return None
