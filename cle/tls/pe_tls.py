import struct

from . import TLSObj

class PETLSObj(TLSObj):
    """
    This class is used when parsing the Thread Local Storage of a PE binary. It
    represents both the TLS array and the TLS data area for a specific thread.

    In memory the ``PETLSObj`` is laid out as follows::

        |----------------------|---------------------------------------|
        | TLS array            | TLS data area                         |
        |----------------------|---------------------------------------|

    A more detailed description of the TLS array and TLS data areas is given
    below.

    TLS array
    ---------

    The TLS array is an array of addresses that points into the TLS data area.
    In memory it is laid out as follows::

        |---------|---------|-----|---------|
        | address | address | ... | address |
        |---------|---------|-----|---------|
         index = 0 index = 1       index = n

    The size of each address is architecture independant (e.g. on X86 it is
    4 bytes). The number of addresses in the TLS array is equal to the number
    of modules that contain TLS data. At load time (i.e. in the ``finalize``
    method), each module is assigned an index into the TLS array. The address
    of this module's TLS data area is then stored at this location in the
    array.

    TLS data area
    -------------

    The TLS data area directly follows the TLS array and contains the actual
    TLS data for each module. In memory it is laid out as follows::

        |----------|-----------|----------|-----------|-----|
        | TLS data | zero fill | TLS data | zero fill | ... |
        |----------|-----------|----------|-----------|-----|
                module a               module b

    The size of each module's TLS data area is variable and can be found in the
    module's ``tls_data_size`` property. The same applies to the zero fill. At
    load time (i.e in the ``finalize`` method), the initial TLS data values are
    copied into the TLS data area. Because a TLS index is also assigned to each
    module, we can access a module's TLS data area using this index into the
    TLS array to get the start address of the TLS data.
    """

    def __init__(self, modules):
        super(PETLSObj, self).__init__(modules, filetype='pe')

        # The total size of the TLS object is the sum of each module's TLS data
        # address, the size of the data block in the TLS template and the
        # size of the zero fill
        self._size = 0
        for m in modules:
            self._size += (self.arch.bytes +        # Size of the TLS data's address
                           m.tls_data_size +        # Size of the actual TLS data
                           m.tls_size_of_zero_fill) # Size of the zero fill

    def finalize(self):
        struct_fmt = self.arch.struct_fmt()
        array = []      # The TLS array
        data_area = []  # The TLS data area
        data_offset = len(self.modules) * self.arch.bytes   # The TLS data area directly follows the TLS array, so skip this memory

        for i, m in enumerate(self.modules):
            # Assign the value of the TLS index to the place indicated by the
            # TLS directory's Address of Index field
            m.memory.write_bytes(m.tls_index_address - m.rebase_addr,
                                 struct.pack(struct_fmt, i))

            # Keep track of the TLS data's start address and insert it into the
            # TLS array
            array.append(struct.pack(struct_fmt, data_offset))
            data_offset += m.tls_data_size + m.tls_size_of_zero_fill

            # Copy the TLS data template into the TLS data area. Append the
            # zero fill
            data_area.append('%s%s' % (''.join(m.memory.read_bytes(m.tls_data_start - m.rebase_addr, m.tls_data_size)),
                                       '\0' * m.tls_size_of_zero_fill))

        self.memory.add_backer(0, '%s%s' % (''.join(array), ''.join(data_area)))

    def get_tls_data_addr(self, tls_idx):
        """
        Get the start address of a module's TLS data area via the module's TLS
        index.

        From the PE/COFF spec:

            The code uses the TLS index and the TLS array location (multiplying
            the index by the word size and using it as an offset into the
            array) to get the address of the TLS data area for the given
            program and module.
        """
        if tls_idx < len(self.modules):
            return self.rebase_addr + self.memory.read_addr_at(tls_idx * self.arch.bytes)
        else:
            raise IndexError('TLS index out of range')

    def get_min_addr(self):
        return self.rebase_addr

    def get_max_addr(self):
        return self.rebase_addr + self._size
