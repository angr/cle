__all__ = (
    'CLEError',
    'CLEUnknownFormatError',
    'CLEFileNotFoundError',
    'CLEInvalidBinaryError',
    'CLEOperationError',
)

class CLEError(Exception):
    pass


class CLEUnknownFormatError(CLEError):
    pass


class CLEFileNotFoundError(CLEError):
    pass


class CLEInvalidBinaryError(CLEError):
    pass


class CLEOperationError(CLEError):
    pass


class CLECompatibilityError(CLEError):
    pass
