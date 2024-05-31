import logging
import struct
from io import BytesIO

from cle.errors import CLEError

from .backend import Backend, register_backend

try:
    import cart
except ImportError:
    cart = None

log = logging.getLogger(__name__)


class CARTFile(Backend):
    """
    The CaRT file format is used to store/transfer malware and its associated metadata. It neuters the malware so it
    cannot be executed and encrypts it so anti-virus software cannot flag the CaRT file as malware.

    Ref: https://github.com/CybercentreCanada/cart
    """

    is_default = True

    def __init__(self, binary, binary_stream, *args, arc4_key=None, **kwargs):
        if cart is None:
            raise CLEError(
                "Please install the cart Python package before loading a CART file. You may run `pip install cart`."
            )
        super().__init__(binary, binary_stream, *args, **kwargs)

        # hack: we are using a loader internal method in a non-kosher way which will cause our children to be
        # marked as the main binary if we are also the main binary
        # work around this by setting ourself here:
        ostream = BytesIO()
        _ = cart.unpack_stream(
            binary_stream,
            ostream,
            arc4_key_override=arc4_key,
        )
        if self.loader._main_object is None:
            self.loader._main_object = self
        child = self.loader._load_object_isolated(ostream)
        self.child_objects.append(child)
        self.has_memory = False

        if self.loader._main_object is self:
            # clean up the main_object after use
            self.loader._main_object = None

        self.force_main_object = child  # the loader will pick it up

    @classmethod
    def is_compatible(cls, stream) -> bool:
        stream.seek(0)
        header = stream.read(6)
        stream.seek(0)
        if len(header) != 6:
            return False
        (magic, version) = struct.unpack("4sh", header)
        return magic == b"CART" and version == 1


register_backend("cart", CARTFile)
