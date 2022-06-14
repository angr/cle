from .register_class import RegisterClass


def get_allocator():
    return RegisterAllocator()


def get_return_allocator():
    return ReturnValueAllocator()


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

    def update_framebase_from_type(self, param):
        """
        Get a framebase for a variable based on stack location and type
        Framebase values must be 8 byte aligned.
        """
        self.framebase += self.next_multiple_eight(param.get("size", 0))

    def next_framebase_from_type(self, param) -> str:
        framebaseStr = "framebase+" + str(self.framebase)
        # Update the framebase for the next parameter based on the type
        self.update_framebase_from_type(param)
        return framebaseStr


class RegisterAllocator:
    """
    A RegisterAllocator can provide the next register location
    """

    def __init__(self):
        self.sse_registers = []
        # Populate the sse register stack
        # [7, 6, 5, 4, 3, 2, 1, 0]
        for i in range(7, -1, -1):
            self.sse_registers.append("%xmm" + str(i))

        # Add a framebase allocator
        self.fallocator = FramebaseAllocator()
        self.int_registers = ["%r9", "%r8", "%rcx", "%rdx", "%rsi", "%rdi"]
        self.framebase = 8

    def get_register_string(self, lo, hi, param) -> str:
        """
        Given two registers, return one combined string
        """
        # Empty structs and unions don't have a location
        if lo == RegisterClass.NO_CLASS and (
            param["class"] == "Union" or param["class"] == "Struct"
        ):
            return "none"
        if lo == RegisterClass.NO_CLASS:
            raise ValueError("Can't allocate a {NO_CLASS, *}")

        if lo == RegisterClass.MEMORY:
            # goes on the stack
            return self.fallocator.next_framebase_from_type(param)

        if lo == RegisterClass.INTEGER:
            reg = self.get_next_int_register()
            if not reg:
                # Ran out of registers, put it on the stack
                return self.fallocator.next_framebase_from_type(param)
            return reg

        if lo == RegisterClass.SSE:
            reg = self.get_next_sse_register()
            if not reg:
                return self.fallocator.next_framebase_from_type(param)

            if hi == RegisterClass.SSEUP:
                # If the class is SSEUP, the eightbyte is passed in the next available eightbyte
                # chunk of the last used vector register.
                pass
            return reg

        # TODO: For objects allocated in multiple registers, use the syntax '%r1 | %r2 | ...'
        # to denote this. This can only happen for aggregates.
        # Use ymm and zmm for larger vector types and check for aliasing

        # If the class is X87, X87UP or COMPLEX_X87, it is passed in memory
        if (
            lo == RegisterClass.X87
            or lo == RegisterClass.COMPLEX_X87
            or hi == RegisterClass.X87UP
        ):
            return self.fallocator.next_framebase_from_type(param)

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
    def get_register_string(self, lo, param, hi=None) -> str:
        """
        TODO: The standard does not describe how to return aggregates and unions
        """
        if lo == RegisterClass.MEMORY:
            # If the type has class MEMORY, then the caller provides space for the return
            # value and passes the address of this storage in %rdi as if it were the first
            # argument to the function. In effect, this address becomes a “hidden” first ar-
            # gument. This storage must not overlap any data visible to the callee through
            # other names than this argument.
            # On return %rax will contain the address that has been passed in by the
            # caller in %rdi.
            return "%rax"

        if lo == RegisterClass.INTEGER:
            # If the class is INTEGER, the next available register of the sequence %rax, %rdx is used.
            if param.get("size", 0) > 64:
                return "%rax|%rdx"
            return "%rax"

        if lo == RegisterClass.SSE:
            #  If the class is SSE, the next available vector register of the sequence %xmm0, %xmm1 is used
            # TODO: larger vector types (ymm, zmm)
            if param.get("size", 0) > 64:
                return "%xmm0|%xmm1"
            return "%xmm0"

        if lo == RegisterClass.SSEUP:
            # If the class is SSEUP, the eightbyte is returned in the next available eightbyte
            # chunk of the last used vector register.
            return "SSEUP"

        if lo == RegisterClass.X87 or lo == RegisterClass.X87UP:
            # If the class is X87, the value is returned on the X87 stack in %st0 as 80-bit x87 number.
            return "%st0"

        if lo == RegisterClass.COMPLEX_X87:
            # If the class is COMPLEX_X87, the real part of the value is returned in
            # %st0 and the imaginary part in %st1.
            return "%st0|%st1"

        # This should never be reached
        raise RuntimeError("Unable to allocate return value")
