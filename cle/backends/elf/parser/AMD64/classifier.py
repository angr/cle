from .register_class import RegisterClass
from .allocators import RegisterAllocator
from ...types import ClassType

import json
import hashlib
import copy


class Classification:
    def __init__(self, name, regclass):
        self.regclass = regclass
        self.name = name


def hashify(typ):
    dumped = json.dumps(typ, sort_keys=True)
    return hashlib.md5(dumped.encode("utf-8")).hexdigest()


class Eightbyte:
    def __init__(self):
        self.fields = []
        self.size = 0
        self.regclass = RegisterClass.NO_CLASS

    def has_space_for(self, f):
        try:
            return (self.size + f.get("size") or 0) <= 8
        except:
            return False

    def add(self, f, type_uid):
        self.size += f.get("size", 0) or 0

        # Don't add original reference so it mucks up types
        f = copy.deepcopy(f)
        f["type_uid"] = type_uid
        self.fields.append(f)

    def do_print(self):
        for f in self.fields:
            print("{%s,%s}" % (f.get("name"), f.get("size", 0)))


def classify_pointer():
    return Classification("Pointer", RegisterClass.INTEGER)


def classify_reference():
    return Classification("Reference", RegisterClass.INTEGER)


def classify(typ, types=None):
    """
    Main entrypoint to classify something - we return a location string (for non
    aggregate types) OR an updated types that includes new locations for aggregates.
    """
    types = types or {}

    # Don't handle this case right now
    if not typ or "class" not in typ or typ["class"] in ["Unknown", "ComplexUnknown"]:
        return

    cls = None
    classname = typ.get("class")

    # TypeDefs without class get underlying type
    if typ.get("class") == "TypeDef":
        classtyp = typ
        while "underlying_type" in classtyp:
            classtyp = classtyp["underlying_type"]
            if "class" in classtyp:
                classname = classtyp["class"]

    if classname == "Pointer":
        cls = classify_pointer()
    elif classname == "Reference":
        cls = classify_reference()

    elif classname in [
        "Scalar",
        "Integer",
        "Integral",
        "Float",
        "ComplexFloat",
        "Boolean",
    ]:
        cls = classify_scalar(typ, classname=classname, types=types)
    elif classname == "Enum":
        cls = classify_enum(typ)
    elif classname == "Struct":
        cls = classify_struct(typ, types=types)
    elif classname == "Union":
        cls = classify_union(typ, types=types)
    elif classname == "Array":
        cls = classify_array(typ, types=types)

        # If we don't know the underlying type
        if not cls:
            return

    elif classname == "Class":
        cls = classify_class(typ, types=types)
    elif classname == "Function":

        # Functions that aren't pointers
        cls = classify_function(typ)
        if not cls:
            return

    # https://refspecs.linuxbase.org/elf/x86_64-abi-0.21.pdf
    # A null pointer (for all types) has the value zero p 12 ABI document
    elif classname == "Unspecified" and typ.get("size") == 0:
        return "nullptr"
    return cls


def classify_scalar(typ, size=None, classname=None, types=None):
    """
    Classify a scalar type
    """
    types = types or {}
    classname = classname or typ.get("class")

    # size in BITS
    size = size or typ.get("size", 0) * 8

    # Integral types
    if classname in ["Integer", "Boolean"]:  # TODO props.is_UTF?
        if size > 128:

            # TODO this should be some kind of eightbytes thing?
            # berkeley-db-18.1.40-c7okyaricn3s5wx6lqo2exspq6tuninj/lib/libdb-18.1.so...
            return
            raise ValueError("We don't know how to classify IntegerVec size > 128")

        # We know that we need two eightbytes
        if size == 128:
            # Since we check __128 in base type parsing and reformat at struct,
            # we should never hit this case
            # But this one does :)
            # arpack-ng-3.4.0-nwftltslcbp5rcibuoxoerl5caqcdqzn/lib/libparpack.so
            return
            raise ValueError("We should not be parsing a size == 128.")

        # _Decimal32, _Decimal64, and __m64 are supposed to be SSE.
        # TODO How can we differentiate them here?
        return Classification("Integer", RegisterClass.INTEGER)

    if classname in ["Float", "ComplexFloat"]:
        if classname == "ComplexFloat":

            # x87 `complex long double`
            # These are wrong
            if size == 128:
                Classification("ComplexFloat", RegisterClass.COMPLEX_X87)

            # This is NOT correct.
            # TODO It should be struct{T r,i;};, but we don't handle aggregates yet
            return Classification("ComplexFloat", RegisterClass.MEMORY)

        if size <= 64:
            # 32- or 64-bit floats
            return Classification("Float", RegisterClass.SSE)

        if size == 128:
            # x87 `long double` OR __m128[d]
            # TODO: How do we differentiate the vector type here? Dyninst should help us
            return Classification("Float", RegisterClass.X87)

        if size > 128:
            return Classification("FloatVec", RegisterClass.SSE)

    # // TODO we will eventually want to throw this
    # // throw std::runtime_error{"Unknown scalar type"};
    return Classification("Unknown", RegisterClass.NO_CLASS)


def merge(first, second):
    """
    Page 21 (bottom) AMD64 ABI - method to come up with final classification based on two
    """
    # a. If both classes are equal, this is the resulting class.
    if first == second:
        return first

    # b. If one of the classes is NO_CLASS, the resulting class is the other
    if first == RegisterClass.NO_CLASS:
        return second

    if second == RegisterClass.NO_CLASS:
        return first

    # (c) If one of the classes is MEMORY, the result is the MEMORY class.
    if second == RegisterClass.MEMORY or first == RegisterClass.MEMORY:
        return RegisterClass.MEMORY

    # (d) If one of the classes is INTEGER, the result is the INTEGER.
    if second == RegisterClass.INTEGER or first == RegisterClass.INTEGER:
        return RegisterClass.INTEGER

    # (e) If one of the classes is X87, X87UP, COMPLEX_X87 class, MEMORY is used as class.
    if (
        second == RegisterClass.X87
        or second == RegisterClass.X87UP
        or second == RegisterClass.COMPLEX_X87
    ):
        return RegisterClass.MEMORY

    if (
        first == RegisterClass.X87
        or first == RegisterClass.X87UP
        or first == RegisterClass.COMPLEX_X87
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
    return lo, hi


def classify_struct(typ, types=None):
    return classify_aggregate(typ, "Struct", types=types)


def classify_class(typ, types=None):
    return classify_aggregate(typ, "Class", types=types)


def classify_aggregate(typ, aggregate="Struct", types=None):

    size = typ.get("size", 0)
    types = types or {}

    # If an object is larger than eight eightbyes (i.e., 64) class MEMORY.
    # Note there is a double check here because we don't have faith in the size field
    if size > 64:
        return Classification(aggregate, RegisterClass.MEMORY)

    ebs = []
    cur = Eightbyte()
    fields = copy.deepcopy(typ.get("fields", []))
    while fields:
        f = fields.pop(0)
        field = types.get(f.get("type"))
        if not field:
            continue

        # If we have another aggregate (I'm not sure this is correct)
        if field.get("class") in ["Union", "Struct", "Class"]:
            fields = copy.deepcopy(field.get("fields", [])) + fields
            continue
        if field.get("class") == "TypeDef":
            field = field["underlying_type"]

        if not cur.has_space_for(field):
            ebs.append(cur)
            cur = Eightbyte()

        # Store the type uid with the field
        cur.add(field, f.get("type"))

    # If we didn't add the current eightbyte
    if cur.size > 0:
        ebs.append(cur)

    # If the size of an object is larger than eight eightbytes it has class MEMORY
    # This is the double check
    if len(ebs) >= 8:
        return Classification(aggregate, RegisterClass.MEMORY)

    # There should be one classification per eightbyte
    for eb in ebs:

        # Empty structures
        if not eb.fields:
            continue

        fields = copy.deepcopy(eb.fields)

        merged = None
        while fields:

            # We can combine / merge two fields
            if len(fields) >= 2:
                field1 = fields.pop(0)
                field2 = fields.pop(0)
                c1 = classify(field1, types=types)
                c2 = classify(field2, types=types)

                # This will be incorrect if we cannot classify either,
                # but it's better this way than to raise an error and get
                # no result (albeit imperfect).
                if c1 and c2:
                    merged = merge(c1.regclass, c2.regclass)
            else:
                field1 = fields.pop(0)
                c1 = classify(field1, types=types)
                if merged and c1 and c1.regclass:
                    merged = merge(merged, c1.regclass)
                elif c1 and c1.regclass:
                    merged = c1.regclass
        eb.regclass = merged
    return Classification(aggregate, ebs)


def classify_union(typ, types):
    """
    Matt's model does not account for unions
    """
    # TODO update when we know how to handle array eightbytes
    return Classification("Union", RegisterClass.MEMORY)
    # return classify_aggregate(typ, "Union", types=types)


def classify_array(typ, types=None):
    size = typ.get("size", 0)
    types = types or {}

    # If size > 64 or unaligned fields, class memory
    if size > 64:
        return Classification("Array", RegisterClass.MEMORY)

    # Array has underlying type
    typename = typ.get("underlying_type", {}).get("type")
    classname = None

    # regular class id or pointer
    while typename and len(typename) == 32:
        newtype = types[typename]
        if "type" in newtype:
            typename = newtype["type"]
        elif "class" in newtype:
            classname = newtype["class"]
            break

    # This is wrong, but we can't return if we don't know
    # binutils-2.24-me2y7na3wmjftzdtjjse4grksibzjq2q/lib/libbfd-2.24.so...
    if not typename:
        return

    if not classname:
        classname = ClassType.get(typename)

    # Just classify the base type
    base_type = {"class": classname, "size": size}
    return classify(base_type, types=types)


def classify_enum(typ):
    return Classification("Enum", RegisterClass.INTEGER)


def classify_function(typ):
    # TODO this assumes all functions provided are pointers
    # auto [underlying_type, ptr_cnt] = unwrap_underlying_type(t);
    return classify_pointer()
    # Return no class
