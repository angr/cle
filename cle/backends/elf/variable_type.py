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
    def __init__(self, name: str, byte_size:int, elf_object):
        self.name = name
        self.byte_size = byte_size
        self._elf_object = elf_object

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        entry method to read a DW_TAG_..._type
        """
        if die.tag == 'DW_TAG_base_type':
            return VariableBaseType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_pointer_type':
            return VariablePointerType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_structure_type':
            return VariableStructureType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_member':
            return VariableMemberType.read_from_die(die, elf_object)
        elif die.tag == 'DW_TAG_array_type':
            return VariableArrayType.read_from_die(die, elf_object)
        return None

    @staticmethod
    def supported_die(die: DIE) -> bool:
        return die.tag == 'DW_TAG_base_type'\
            or die.tag == 'DW_TAG_pointer_type'\
            or die.tag == 'DW_TAG_structure_type'\
            or die.tag == 'DW_TAG_member'\
            or die.tag == 'DW_TAG_array_type'


class VariablePointerType(VariableType):
    """
    Entry class for DWARF_TAG_pointer_type. It is inherited from VariableType

    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param pointee_offset:  offset in the compilation_unit of the pointee type

    :ivar pointee_offset:   offset in the compilation_unit of the pointee type
    """

    def __init__(self, byte_size: int, elf_object, pointee_offset: int):
        super().__init__('pointer', byte_size, elf_object)
        self.pointee_offset = pointee_offset

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

        return VariablePointerType(byte_size.value, elf_object, dw_at_type.value)

    @property
    def pointee(self):
        """
        attribute to get the pointee type. Return None if the type is not loaded
        """
        type_list = self._elf_object.type_list
        if self.pointee_offset in type_list.keys():
            return type_list[self.pointee_offset]
        return None

class VariableBaseType(VariableType):
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
        return VariableType(
            dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size.value,
            elf_object
        )


class VariableStructureType(VariableType):
    """
    Entry class for DWARF_TAG_structure_type. It is inherited from VariableType

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param member_offset:   offsets in the compilation_unit of the member type

    :ivar member_offset:    offsets in the compilation_unit of the member type
    :type member_offset:    List[int]
    """

    def __init__(self, name: str, byte_size: int, elf_object, member_offsets):
        super().__init__(name, byte_size, elf_object)
        self.member_offsets = member_offsets

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

        return VariableStructureType(
            dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size.value,
            elf_object,
            member_offsets
        )

    @property
    def members(self):
        """
        attribute to get a list of all members type.
        Member entry is loaded correspond to the order defined in source code
        Member could be None if the type is not loaded (not supported)
        """
        members = []
        type_list = self._elf_object.type_list
        for member_offset in self.member_offsets:
            if member_offset in type_list.keys():
                members.append(type_list[member_offset].reference_type)
            else:
                members.append(None)
        return members


class VariableMemberType(VariableType):
    """
    Entry class for DWARF_TAG_member_type. It is inherited from VariableType

    :param name:            name of the member type
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param reference_offset:  offset in the compilation_unit of the reference type

    :ivar reference_offset:   offset in the compilation_unit of the reference type
    """

    def __init__(self, name: str, elf_object, reference_offset):
        super().__init__(name, None, elf_object)
        self.reference_offset = reference_offset

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
        return VariableMemberType(
            dw_at_name.value.decode() if dw_at_name is not None else 'unknown',
            elf_object,
            dw_at_type.value
        )
    @property
    def reference_type(self):
        """
        attribute to get the reference type. Return None if the type is not loaded
        """

        type_list = self._elf_object.type_list
        if self.reference_offset in type_list.keys():
            return type_list[self.reference_offset]
        return None


class VariableArrayType(VariablePointerType):
    """
    Entry class for DWARF_TAG_array_type. It is inherited from VariableType

    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    :param reference_offset:  offset in the compilation_unit of the reference type

    :ivar reference_offset:   offset in the compilation_unit of the reference type
    """

    def __init__(self, byte_size, elf_object, pointee_offset):
        super().__init__(byte_size, elf_object, pointee_offset)
        self.name = "array"

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
        return VariableArrayType(
            dw_byte_size.value if dw_byte_size is not None else None,
            elf_object,
            dw_at_type.value
        )
