from .clexception import CLException
from .abs_obj import AbsObj

class Blob(AbsObj):
    """
        Representation of a binary blob, i.e., an executable in an unknown file
        format.
    """

    def __init__(self, *args, **kwargs):
        """
        Arguments we expect in kwargs:
            @custom_entry_point: where to start the execution in the blob
            @custom_base_address: at which address shall we load the blob ?
            @custom_offset: skip n bytes from the beginning of the file, where
                n = @custom_offset
        """

        if 'custom_entry_point' not  in kwargs or \
            'custom_base_address' not in kwargs or \
            'custom_offset' not in kwargs:
                raise CLException("Not enought arguments supplied to load this blob")

        super(Blob, self).__init__(*args, **kwargs)
