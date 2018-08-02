from . import TLSObject, InternalTLSRelocation
from ...address_translator import AT
from ...errors import CLEError

class PETLSObject(TLSObject):
    """
    This class is used when parsing the Thread Local Storage of a PE binary. It
    represents both the TLS array and the TLS data area for a specific thread.

    In memory the ``PETLSObj`` is laid out as follows::

        +----------------------+---------------------------------------+
        | TLS array            | TLS data area                         |
        +----------------------+---------------------------------------+

    A more detailed description of the TLS array and TLS data areas is given
    below.

    **TLS array**

    The TLS array is an array of addresses that points into the TLS data area.
    In memory it is laid out as follows::

        +-----------+-----------+-----+-----------+
        |  address  |  address  | ... |  address  |
        +-----------+-----------+-----+-----------+
        | index = 0 | index = 1 |     | index = n |
        +-----------+-----------+-----+-----------+

    The size of each address is architecture independent (e.g. on X86 it is
    4 bytes). The number of addresses in the TLS array is equal to the number
    of modules that contain TLS data. At load time (i.e. in the ``finalize``
    method), each module is assigned an index into the TLS array. The address
    of this module's TLS data area is then stored at this location in the
    array.

    **TLS data area**

    The TLS data area directly follows the TLS array and contains the actual
    TLS data for each module. In memory it is laid out as follows::

        +----------+-----------+----------+-----------+-----+
        | TLS data | zero fill | TLS data | zero fill | ... |
        +----------+-----------+----------+-----------+-----+
        |       module a       |       module b       | ... |
        +---------------------------------------------------+

    The size of each module's TLS data area is variable and can be found in the
    module's ``tls_data_size`` property. The same applies to the zero fill. At
    load time (i.e in the ``finalize`` method), the initial TLS data values are
    copied into the TLS data area. Because a TLS index is also assigned to each
    module, we can access a module's TLS data area using this index into the
    TLS array to get the start address of the TLS data.
    """

    def __init__(self, loader, max_modules=256, max_data=0x8000):
        super(PETLSObject, self).__init__(loader)
        self.max_modules = max_modules
        self.max_data = max_data

        self.used_data = 0
        self.next_module_id = 0
        self.data_start = self.arch.bytes*max_modules

        self.memory.add_backer(0, b'\0'*self.data_start)

    def register_object(self, obj):
        if not obj.tls_used:
            return

        super(PETLSObject, self).register_object(obj)

        obj.tls_module_id = self.next_module_id
        self.next_module_id += 1
        if self.next_module_id > self.max_modules:
            raise CLEError("Too many loaded modules for TLS to handle... file this as a bug")

        data_start = self.data_start + self.used_data
        obj.tls_data_pointer = AT.from_rva(data_start, self).to_mva()
        self.used_data += obj.tls_data_size + obj.tls_size_of_zero_fill
        if self.used_data > self.max_data:
            raise CLEError("Too much TLS data to handle... file this as a bug")

        # The PE TLS header says to write its index into a given address
        obj.memory.write_addr_at(AT.from_lva(obj.tls_index_address, obj).to_rva(), obj.tls_module_id)

        # Write the address of the data start into the array
        self.memory.write_addr_at(obj.tls_module_id*self.arch.bytes, AT.from_rva(data_start, self).to_mva())
        self.relocs.append(InternalTLSRelocation(data_start, obj.tls_module_id*self.arch.bytes, self))

    def map_object(self, obj):
        # Add the data image
        obj.memory.seek(AT.from_lva(obj.tls_data_start, obj).to_rva())
        image = obj.memory.read(obj.tls_data_size) + b'\0'*obj.tls_size_of_zero_fill
        self.memory.add_backer(AT.from_mva(obj.tls_data_pointer, self).to_rva(), image)

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
        if 0 <= tls_idx < self.next_module_id:
            return self.memory.read_addr_at(tls_idx * self.arch.bytes)
        else:
            raise IndexError('TLS index out of range')

    @property
    def max_addr(self):
        return self.mapped_base + self.data_start + self.used_data

    # PE is MUCH simpler in terms of what's the pointer to the thread data. Add these properties for compatibility.

    @property
    def thread_pointer(self):
        return self.mapped_base

    @property
    def user_thread_pointer(self):
        return self.mapped_base
