__all__ = ('CLEError', 'CLEUnknownFormatError', 'CLEAddrError')

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


class CLEAddrError(CLEError):
    pass
