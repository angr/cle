class CLException(Exception):
    def __init__(self, val):
        super(CLException, self).__init__(val)
        self.val = val

    def __str__(self):
        return repr(self.val)


class UnknownFormatException(CLException):
    pass

class CLEAddrException(CLException):
    pass
