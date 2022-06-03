from enum import Enum


class RegisterClass(Enum):
    """
    A register class for AMD64 is defined on page 16 of the System V abi pdf
    """

    INTEGER = 1  # Integer types that fit into one of the general purpose registers
    SSE = 2  # Types that fit into an SSE register
    SSEUP = 3  # ^.. and can ve passed and returned in he most significant half of it
    X87 = 4  # Types that will be returned via the x87 FPU
    X87UP = 5  # ^
    COMPLEX_X87 = 6  # Types that will be returned via the x87 FPU
    NO_CLASS = 7  # Initalizer in the algorithms, used for padding and empty
    # tructures and unions
    MEMORY = 8  # Types that will be passed and returned in memory via the stack
