from elftools.dwarf.die import DIE


class VariableType:
    """
    Entry class for DW_TAG_..._type

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
        elif die.tag == 'DW_TAG_array_type':
            return ArrayType.read_from_die(die, elf_object)
        return None

    @staticmethod
    def supported_die(die: DIE) -> bool:
        return die.tag in ('DW_TAG_base_type',
                           'DW_TAG_pointer_type',
                           'DW_TAG_structure_type',
                           'DW_TAG_array_type')


class PointerType(VariableType):
    """
    Entry class for DW_TAG_pointer_type. It is inherited from VariableType

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
            referenced_offset = None
        else:
            referenced_offset = dw_at_type.value + die.cu.cu_offset

        return PointerType(byte_size.value, elf_object, referenced_offset)

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
    Entry class for DW_TAG_base_type. It is inherited from VariableType
    """

    # for __init__ see VariableType

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
    Entry class for DW_TAG_structure_type. It is inherited from VariableType

    :param name:            name of the type
    :param byte_size:       amount of bytes the type take in memory
    :param elf_object:      elf object to reference to (useful for pointer,...)
    """

    def __init__(self, name: str, byte_size: int, elf_object, members):
        super().__init__(name, byte_size, elf_object)
        self.members = members

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

        members = []
        for die_child in die.iter_children():
            if die_child.tag == 'DW_TAG_member':
                members.append(StructMember.read_from_die(die_child, elf_object))

        return StructType(
            dw_at_name.value.decode() if dw_at_name is not None else "unknown",
            byte_size.value,
            elf_object,
            members
        )

    def __getitem__(self, member_name):
        for member in self.members:
            if member.name == member_name:
                return member
        raise KeyError


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

    @staticmethod
    def read_from_die(die: DIE, elf_object):
        """
        read an entry of DW_TAG_member_type. return None when there is no
        type attribute.
        """

        dw_at_name   = die.attributes.get('DW_AT_name', None)
        dw_at_type   = die.attributes.get('DW_AT_type', None)
        dw_at_memloc = die.attributes.get('DW_AT_data_member_location', None)
        name        = None if dw_at_name   is None else dw_at_name.value.decode()
        ty          = None if dw_at_type   is None else dw_at_type.value + die.cu.cu_offset
        addr_offset = None if dw_at_memloc is None else dw_at_memloc.value

        return StructMember(name, addr_offset, ty, elf_object)

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
            dw_at_type.value + die.cu.cu_offset
        )

    @property
    def element_type(self):
        type_list = self._elf_object.type_list
        if self._element_offset in type_list.keys():
            return type_list[self._element_offset]
        return None
