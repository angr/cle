import copy
from .register_class import RegisterClass

int_registers = ["%r9", "%r8", "%rcx", "%rdx", "%rsi", "%rdi"]


def get_allocator():
    return RegisterAllocator()


def get_return_allocator():
    return ReturnValueAllocator()


def get_sse_registers():
    # Populate the sse register stack
    # [7, 6, 5, 4, 3, 2, 1, 0]
    regs = []
    for i in range(7, -1, -1):
        regs.append("%xmm" + str(i))
    return regs


class FramebaseAllocator:
    """
    A FramebaseAllocator keeps track of framebase index
    """

    def __init__(self):
        self.framebase = 8

    def next_multiple_eight(self, number):
        """
        Get the next greater multiple of 8
        """
        return (number + 7) & (-8)

    def update_framebase_from_type(self, size):
        """
        Get a framebase for a variable based on stack location and type
        Framebase values must be 8 byte aligned.
        """
        self.framebase += self.next_multiple_eight(size)

    def next_framebase_from_type(self, size) -> str:
        framebaseStr = "framebase+" + str(self.framebase)
        # Update the framebase for the next parameter based on the type
        self.update_framebase_from_type(size)
        return framebaseStr


class RegisterAllocator:
    """
    A RegisterAllocator can provide the next register location
    """

    def __init__(self):
        self.sse_registers = get_sse_registers()

        # Add a framebase allocator
        self.fallocator = FramebaseAllocator()
        self.int_registers = copy.deepcopy(int_registers)
        self.framebase = 8
        self.transaction_start = None

    def start_transaction(self):
        """
        Keep the state of the start of the transaction (an aggregate)
        """
        # Only record state if we aren't currently in a transaction (e.g. nested aggregates)
        if not self.transaction_start:
            self.transaction_start = (
                copy.deepcopy(self.int_registers),
                copy.deepcopy(self.sse_registers),
                self.fallocator.framebase,
            )

    def end_transaction(self):
        """
        End a successful transaction.
        """
        self.transaction_start = None

    def rollback(self):
        """
        Given we run out of registers, roll back to before we started aggregate allocation.
        """
        if not self.transaction_start:
            raise ValueError("Rollback called while not in a transaction!")
        self.fallocator.framebase = self.transaction_start[2]
        self.int_registers = self.transaction_start[0]
        self.sse_registers = self.transaction_start[1]
        self.transaction_start = None

    def get_register_string(self, reg, size) -> str:
        """
        Given two registers, return one combined string
        """
        if reg == RegisterClass.NO_CLASS:
            raise ValueError("Can't allocate a {NO_CLASS, *}")

        if reg == RegisterClass.MEMORY:
            # goes on the stack
            return self.fallocator.next_framebase_from_type(size)

        if reg == RegisterClass.INTEGER:
            register = self.get_next_int_register()
            if not register:
                # Ran out of registers, put it on the stack
                return self.fallocator.next_framebase_from_type(size)
            return register

        if reg == RegisterClass.SSE:
            register = self.get_next_sse_register()
            if not register:
                return self.fallocator.next_framebase_from_type(size)
            return register

        # TODO: For objects allocated in multiple registers, use the syntax '%r1 | %r2 | ...'
        # to denote this. This can only happen for aggregates.
        # Use ymm and zmm for larger vector types and check for aliasing

        # If the class is X87, X87UP or COMPLEX_X87, it is passed in memory
        if (
            reg == RegisterClass.X87
            or reg == RegisterClass.COMPLEX_X87
            or reg == RegisterClass.X87UP
        ):
            return self.fallocator.next_framebase_from_type(size)

        # This should never be reached - bug in CORE/libperl.so
        # raise RuntimeError("Unknown classification")
        return "unknown"

    def get_next_int_register(self):
        """
        Get the next available integer register
        """
        # If we are empty, return None to get from stack
        if not self.int_registers:
            return None
        return self.int_registers.pop()

    def get_next_sse_register(self):
        if not self.sse_registers:
            return None
        return self.sse_registers.pop()


class ReturnValueAllocator:
    def get_register_string(self, reg, size) -> str:
        """
        TODO: The standard does not describe how to return aggregates and unions
        """
        if reg == RegisterClass.NO_CLASS:
            return "unknown"

        if reg == RegisterClass.MEMORY:
            # If the type has class MEMORY, then the caller provides space for the return
            # value and passes the address of this storage in %rdi as if it were the first
            # argument to the function. In effect, this address becomes a “hidden” first ar-
            # gument. This storage must not overlap any data visible to the callee through
            # other names than this argument.
            # On return %rax will contain the address that has been passed in by the
            # caller in %rdi.
            return "%rax"

        if reg == RegisterClass.INTEGER:
            # If the class is INTEGER, the next available register of the sequence %rax, %rdx is used.
            if size > 64:
                return "%rax|%rdx"
            return "%rax"

        # TODO: second part was added finding lo=None, and hi=SSE, see adios->libadios2_cxx11.so
        if reg == RegisterClass.SSE:
            #  If the class is SSE, the next available vector register of the sequence %xmm0, %xmm1 is used
            # TODO: larger vector types (ymm, zmm)
            if size > 64:
                return "%xmm0|%xmm1"
            return "%xmm0"

        if reg == RegisterClass.SSEUP:
            # If the class is SSEUP, the eightbyte is returned in the next available eightbyte
            # chunk of the last used vector register.
            return "SSEUP"

        if reg == RegisterClass.X87:
            # If the class is X87, the value is returned on the X87 stack in %st0 as 80-bit x87 number.
            return "%st0"

        if reg == RegisterClass.COMPLEX_X87:
            # If the class is COMPLEX_X87, the real part of the value is returned in
            # %st0 and the imaginary part in %st1.
            return "%st0|%st1"

        raise RuntimeError("Unable to allocate return value")
