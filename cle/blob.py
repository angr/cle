from .clexception import CLException
from .abs_obj import AbsObj
import logging

l = logging.getLogger("cle.blob")

class Blob(AbsObj):
    """
        Representation of a binary blob, i.e., an executable in an unknown file
        format.
    """

    def __init__(self, *args, **kwargs):
        """
        Arguments we expect in kwargs:
            @custom_entry_point: where to start the execution in the blob
            @custom_base_addr: at which address shall we load the blob ?
            @custom_offset: skip n bytes from the beginning of the file, where
                n = @custom_offset
        """

        if 'custom_entry_point' not  in kwargs or \
                'custom_base_addr' not in kwargs or \
                'custom_arch' not in kwargs:
            raise CLException("Not enought arguments supplied to load this blob (Blob needs custom_entry_point, custom_base_addr and custom_arch passed as cle_options)")

        if 'custom_offset' not in kwargs:
            l.warning("No custom offset was specified for blob, assuming 0")

        kwargs['blob'] = True
        super(Blob, self).__init__(*args, **kwargs)
