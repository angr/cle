__all__ = (
    'CLEError',
    'CLEUnknownFormatError',
    'CLEFileNotFoundError',
    'CLEInvalidBinaryError',
    'CLEOperationError',
    'CLECompatibilityError',
)

class CLEError(Exception):
    """
    Base class for errors raised by CLE.
    """
    pass


class CLEUnknownFormatError(CLEError):
    """
    Error raised when CLE encounters an unknown executable file format.
    """
    pass


class CLEFileNotFoundError(CLEError):
    """
    Error raised when a file does not exist.
    """
    pass


class CLEInvalidBinaryError(CLEError):
    """
    Error raised when an executable file is invalid or corrupted.
    """
    pass


class CLEOperationError(CLEError):
    """
    Error raised when a problem is encountered in the process of loading an executable.
    """
    pass


class CLECompatibilityError(CLEError):
    """
    Error raised when loading an executable that is not currently supported by CLE.
    """
    pass

class CLEMemoryError(CLEError):
    """
    Error raised when performing memory operations on unmapped addresses
    """
    pass
