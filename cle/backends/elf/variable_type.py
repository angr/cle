from elftools.dwarf.die import DIE


class VariableType:
    """
    Entry class for DWARF_TAG_..._type

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory

    :ivar name:             name of the type
    :type name:             str
    :ivar byte_size:        amount of bytes the type take in memory
    """
    def __init__(self, name: str, byte_size:int):
        self.name = name
        self.byte_size = byte_size

    @staticmethod
    def read_from_die(die: DIE):
        """
        entry method to read a DW_TAG_..._type
        """
        if die.tag == 'DW_TAG_base_type':
            return VariableBaseType.read_from_die(die)
        elif die.tag == 'DW_TAG_pointer_type':
            return VariablePointerType.read_from_die(die)
        elif die.tag == 'DW_TAG_structure_type':
            return VariableStructureType.read_from_die(die)
        elif die.tag == 'DW_TAG_member':
            return VariableMemberType.read_from_die(die)
        elif die.tag == 'DW_TAG_array_type':
            return VariableArrayType.read_from_die(die)
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
    :param pointee_offset:  offset in the compilation_unit of the pointee type

    :ivar pointee_offset:   offset in the compilation_unit of the pointee type
    """

    def __init__(self, byte_size: int, pointee_offset: int):
        super().__init__('pointer', byte_size)
        self.pointee_offset = pointee_offset

    @staticmethod
    def read_from_die(die: DIE):
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

        return VariablePointerType(byte_size.value, dw_at_type.value)


class VariableBaseType(VariableType):
    """
    Entry class for DWARF_TAG_base_type. It is inherited from VariableType
    """

    def __init__(self, name: str, byte_size: int):
        super().__init__(name, byte_size)

    @staticmethod
    def read_from_die(die: DIE):
        """
        read an entry of DW_TAG_base_type. return None when there is no
        byte_size attribute.
        """

        dw_at_name = die.attributes.get("DW_AT_name", None)
        byte_size = die.attributes.get("DW_AT_byte_size", None)
        if byte_size is None:
            return None
        return VariableType(
            name = dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size = byte_size.value
        )


class VariableStructureType(VariableType):
    """
    Entry class for DWARF_TAG_structure_type. It is inherited from VariableType

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory
    :param member_offset:   offsets in the compilation_unit of the member type

    :ivar member_offset:    offsets in the compilation_unit of the member type
    :type member_offset:    List[int]
    """

    def __init__(self, name: str, byte_size: int, member_offsets):
        super().__init__(name, byte_size)
        self.member_offsets = member_offsets

    @staticmethod
    def read_from_die(die: DIE):
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
            member_offsets
        )


class VariableMemberType(VariableType):
    """
    Entry class for DWARF_TAG_member_type. It is inherited from VariableType

    :param name:            name of the member type
    :param reference_offset:  offset in the compilation_unit of the reference type

    :ivar reference_offset:   offset in the compilation_unit of the reference type
    """

    def __init__(self, name: str, reference_offset):
        super().__init__(name, None)
        self.reference_offset = reference_offset

    @staticmethod
    def read_from_die(die: DIE):
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
            dw_at_type.value
        )


class VariableArrayType(VariableType):
    """
    Entry class for DWARF_TAG_array_type. It is inherited from VariableType

    :param byte_size:       amount of bytes the type take in memory
    :param reference_offset:  offset in the compilation_unit of the reference type

    :ivar reference_offset:   offset in the compilation_unit of the reference type
    """

    def __init__(self, byte_size, reference_offset):
        super().__init__("array", byte_size)
        self.reference_offset = reference_offset

    @staticmethod
    def read_from_die(die: DIE):
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
            dw_at_type.value
        )
