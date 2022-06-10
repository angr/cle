from .register_class import RegisterClass
from .allocators import RegisterAllocator
from ...types import ClassType


class Classification:
    def __init__(self, name, classes, count=0):
        self.classes = classes
        self.name = name
        self.pointer_indirections = count


class Eightbyte:
    def __init__(self):
        self.fields = []
        self.size = 0

    def has_space_for(self, f):
        return self.size + f.get("size", 0) <= 8

    def add(self, f):
        self.size += f.get("size", 0)
        self.fields.append(f)

    def do_print(self):
        for f in self.fields:
            print("{%s,%s}" % (f.get("name"), f.get("size", 0)))


def classify_pointer(count):
    return Classification(
        "Pointer", [RegisterClass.INTEGER, RegisterClass.NO_CLASS], count
    )


def classify(typ, count=0, die=None, return_classification=False, allocator=None):
    """
    Main entrypoint to clsasify something
    """
    # Don't handle this case right now
    if "class" not in typ:
        return

    cls = None
    count = count or typ.get("indirections", 0)
    if count > 0 or typ.get("class") == "Pointer":
        cls = classify_pointer(count)

    elif typ["class"] in ["Scalar", "Integer", "Integral", "Float", "Boolean"]:
        cls = classify_scalar(typ)
    elif typ["class"] == "Struct":
        cls = classify_struct(typ, allocator=allocator)
    elif typ["class"] == "Union":
        cls = classify_union(typ, allocator=allocator)
    elif typ["class"] == "Array":
        cls = classify_array(typ, allocator=allocator)
    elif typ["class"] == "Class":
        cls = classify_class(typ, allocator=allocator)

    # https://refspecs.linuxbase.org/elf/x86_64-abi-0.21.pdf
    # A null pointer (for all types) has the value zero p 12 ABI document
    elif typ["class"] == "Unspecified" and typ.get("size") == 0:
        return "nullptr"

    if cls is None:
        print("UNWRAP UNDERLYING TYPE IN CLASSIFY")
        import IPython

        IPython.embed()

    # } else if (auto *t = underlying_type->getEnumType()) {
    #  return classify(t);
    # } else if (auto *t = underlying_type->getFunctionType()) {
    #  return classify(t);
    # }
    # return {RegisterClass::NO_CLASS, RegisterClass::NO_CLASS, "Unknown"};
    if isinstance(cls, Classification) and return_classification:
        return cls

    if isinstance(cls, list) and len(cls) == 1 and not return_classification:
        cls = cls[0]

    if isinstance(cls, list) and len(cls) == 2:
        return allocator.get_register_string(cls[0], cls[1], typ)

    # If a classifier returns the location directly (e.g., struct)
    if not isinstance(cls, Classification):
        return cls

    return allocator.get_register_string(
        lo=cls.classes[0], hi=cls.classes[1], param=typ
    )


def classify_scalar(typ, size=None):
    """
    Classify a scalar type
    """
    # size in BITS
    size = size or typ.get("size", 0) * 8

    # Integral types
    if typ["class"] in ["Integral", "Integer", "Boolean"]:  # TODO props.is_UTF?
        if size > 128:
            return Classification(
                "IntegerVec", [RegisterClass.SSE, RegisterClass.SSEUP]
            )

        if size == 128:
            # __int128 is treated as struct{long,long};
            # This is NOT correct, but we don't handle aggregates yet.
            # How do we differentiate between __int128 and __m128i?
            return Classification(
                "Integer", [RegisterClass.MEMORY, RegisterClass.NO_CLASS]
            )

        # _Decimal32, _Decimal64, and __m64 are supposed to be SSE.
        # TODO How can we differentiate them here?
        return Classification(
            "Integer", [RegisterClass.INTEGER, RegisterClass.NO_CLASS]
        )

    if typ["class"] in ["Float", "ComplexFloat"]:
        if typ["class"] == "ComplexFloat":

            # x87 `complex long double`
            if size == 128:
                Classification(
                    "ComplexFloat", [RegisterClass.COMPLEX_X87, RegisterClass.NO_CLASS]
                )

            # This is NOT correct.
            # TODO It should be struct{T r,i;};, but we don't handle aggregates yet
            return Classification(
                "ComplexFloat", [RegisterClass.MEMORY, RegisterClass.NO_CLASS]
            )

        if size <= 64:
            # 32- or 64-bit floats
            return Classification("Float", [RegisterClass.SSE, RegisterClass.SSEUP])

        if size == 128:
            # x87 `long double` OR __m128[d]
            # TODO: How do we differentiate the vector type here? Dyninst should help us
            return Classification("Float", [RegisterClass.X87, RegisterClass.X87UP])

        if size > 128:
            return Classification("FloatVec", [RegisterClass.SSE, RegisterClass.SSEUP])

    # // TODO we will eventually want to throw this
    # // throw std::runtime_error{"Unknown scalar type"};
    return Classification("Unknown", [RegisterClass.NO_CLASS, RegisterClass.NO_CLASS])


def merge(originalReg, newReg):
    """
    Page 21 (bottom) AMD64 ABI - method to come up with final classification based on two
    """
    # a. If both classes are equal, this is the resulting class.
    if originalReg == newReg:
        return originalReg

    # b. If one of the classes is NO_CLASS, the resulting class is the other
    if originalReg == RegisterClass.NO_CLASS:
        return newReg

    if newReg == RegisterClass.NO_CLASS:
        return originalReg

    # (c) If one of the classes is MEMORY, the result is the MEMORY class.
    if newReg == RegisterClass.MEMORY or originalReg == RegisterClass.MEMORY:
        return RegisterClass.MEMORY

    # (d) If one of the classes is INTEGER, the result is the INTEGER.
    if newReg == RegisterClass.INTEGER or originalReg == RegisterClass.INTEGER:
        return RegisterClass.INTEGER

    # (e) If one of the classes is X87, X87UP, COMPLEX_X87 class, MEMORY is used as class.
    if (
        newReg == RegisterClass.X87
        or newReg == RegisterClass.X87UP
        or newReg == RegisterClass.COMPLEX_X87
    ):
        return RegisterClass.MEMORY

    if (
        originalReg == RegisterClass.X87
        or originalReg == RegisterClass.X87UP
        or originalReg == RegisterClass.COMPLEX_X87
    ):
        return RegisterClass.MEMORY

    # (f) Otherwise class SSE is used.
    return RegisterClass.SSE


def post_merge(lo, hi, size):
    """
    Page 22 AMD64 ABI point 5 - this is the most merger "cleanup"
    """
    # (a) If one of the classes is MEMORY, the whole argument is passed in memory.
    if lo == RegisterClass.MEMORY or hi == RegisterClass.MEMORY:
        lo = RegisterClass.MEMORY
        hi = RegisterClass.MEMORY

    # (b) If X87UP is not preceded by X87, the whole argument is passed in memory.
    if hi == RegisterClass.X87UP and lo != RegisterClass.X87:
        lo = RegisterClass.MEMORY
        hi = RegisterClass.MEMORY

    # (c) If the size of the aggregate exceeds two eightbytes and the first eight- byte isn’t SSE
    # or any other eightbyte isn’t SSEUP, the whole argument is passed in memory.
    if size > 128 and (lo != RegisterClass.SSE or hi != RegisterClass.SSEUP):
        lo = RegisterClass.MEMORY
        hi = RegisterClass.MEMORY

    # (d) If SSEUP is // not preceded by SSE or SSEUP, it is converted to SSE.
    if (
        hi == RegisterClass.SSEUP
        and lo != RegisterClass.SSE
        and lo != RegisterClass.SSEUP
    ):
        hi = RegisterClass.SSE


def classify_struct(typ, allocator=None, return_classification=False):
    return classify_aggregate(typ, allocator, return_classification, "Struct")


def classify_class(typ, allocator=None, return_classification=False):
    return classify_aggregate(typ, allocator, return_classification, "Class")


def classify_aggregate(
    typ, allocator=None, return_classification=False, aggregate="Struct"
):
    size = typ.get("size", 0)

    # If an object is larger than eight eightbyes (i.e., 64) class MEMORY.
    if size > 64:
        return Classification(aggregate, [RegisterClass.MEMORY, RegisterClass.NO_CLASS])

    ebs = []
    cur = Eightbyte()
    added = False
    for f in typ.get("fields", []):
        added = False
        if not cur.has_space_for(f):
            added = True
            ebs.append(cur)
            cur = Eightbyte()
        cur.add(f)

    # If we didn't add the current eightbyte
    if not added and cur.size > 0:
        ebs.append(cur)

    classes = []
    for eb in ebs:
        # vector of temporary classifications
        # tmp = []
        # for f in eb.fields:
        #    tmp.append(classify(f))

        if len(eb.fields) > 1:
            c1 = classify(eb.fields[0], allocator=allocator, return_classification=True)
            c2 = classify(eb.fields[1], allocator=allocator, return_classification=True)
            classes.append(merge(c1, c2))
        else:
            classes.append(
                classify(eb.fields[0], allocator=allocator, return_classification=True)
            )

    has_registers = False
    for c in classes:
        if isinstance(c, RegisterClass):
            has_registers = True
            break
    if has_registers:
        if len(classes) == 1:
            classes.append(RegisterClass.NO_CLASS)
        return Classification(aggregate, classes)
    return classes


def classify_fields(typ):
    """
    Classify the fields
    """
    return [classify(f) for f in typ.get("fields", [])]


def classify_union(typ, allocator):
    size = typ.get("size", 0)
    if size > 64:
        return Classification("Union", [RegisterClass.MEMORY, RegisterClass.NO_CLASS])

    hi = RegisterClass.NO_CLASS
    lo = RegisterClass.NO_CLASS

    # We renamed members to fields
    for f in typ.get("fields", []):
        c = classify(f, allocator=allocator, return_classification=True)
        hi = merge(hi, c.classes[1])
        lo = merge(lo, c.classes[0])

    # Pass a reference so they are updated here, and we also need size
    post_merge(lo, hi, size)
    return Classification("Union", [lo, hi])


def classify_array(typ, allocator):
    size = typ.get("size", 0)
    if size > 64:
        return Classification("Array", [RegisterClass.MEMORY, RegisterClass.NO_CLASS])

    # Just classify the base type
    base_type = {"class": ClassType.get(typ.get("type")), "size": size}
    return classify(base_type, allocator=allocator, return_classification=True)


def classify_enum(typ):
    return Classification("Enum", RegisterClass.INTEGER, RegisterClass.NO_CLASS)


def classify_function(typ):
    print("CLASSIFY FUNC")
    import IPython

    IPython.embed()

    # auto [underlying_type, ptr_cnt] = unwrap_underlying_type(t);
    if count > 0:
        return classify_pointer(count)


def classify_field(field):
    print("CLASSIFY FIELD")
    import IPython

    IPython.embed()
    return classify(field)
