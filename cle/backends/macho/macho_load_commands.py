from enum import IntEnum


class LoadCommands(IntEnum):
    # https://opensource.apple.com/source/cctools/cctools-949.0.1/include/mach-o/loader.h.auto.html
    LC_REQ_DYLD = 0x80000000

    LC_SEGMENT = 0x1
    LC_SYMTAB = 0x2
    LC_SYMSEG = 0x3
    LC_THREAD = 0x4
    LC_UNIXTHREAD = 0x5
    LC_LOADFVMLIB = 0x6
    LC_IDFVMLIB = 0x7
    LC_IDENT = 0x8
    LC_FVMFILE = 0x9
    LC_PREPAGE = 0xA
    LC_DYSYMTAB = 0xB
    LC_LOAD_DYLIB = 0xC
    LC_ID_DYLIB = 0xD
    LC_LOAD_DYLINKER = 0xE
    LC_ID_DYLINKER = 0xF
    LC_PREBOUND_DYLIB = 0x10

    LC_ROUTINES = 0x11
    LC_SUB_FRAMEWORK = 0x12
    LC_SUB_UMBRELLA = 0x13
    LC_SUB_CLIENT = 0x14
    LC_SUB_LIBRARY = 0x15
    LC_TWOLEVEL_HINTS = 0x16
    LC_PREBIND_CKSUM = 0x17

    LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD

    LC_SEGMENT_64 = 0x19
    LC_ROUTINES_64 = 0x1A
    LC_UUID = 0x1B
    LC_RPATH = 0x1C | LC_REQ_DYLD
    LC_CODE_SIGNATURE = 0x1D
    LC_SEGMENT_SPLIT_INFO = 0x1E
    LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
    LC_LAZY_LOAD_DYLIB = 0x20
    LC_ENCRYPTION_INFO = 0x21
    LC_DYLD_INFO = 0x22
    LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
    LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
    LC_VERSION_MIN_MACOSX = 0x24
    LC_VERSION_MIN_IPHONEOS = 0x25
    LC_FUNCTION_STARTS = 0x26
    LC_DYLD_ENVIRONMENT = 0x27

    LC_MAIN = 0x28 | LC_REQ_DYLD
    LC_DATA_IN_CODE = 0x29
    LC_SOURCE_VERSION = 0x2A
    LC_DYLIB_CODE_SIGN_DRS = 0x2B
    LC_ENCRYPTION_INFO_64 = 0x2C
    LC_LINKER_OPTION = 0x2D
    LC_LINKER_OPTIMIZATION_HINT = 0x2E
    LC_VERSION_MIN_TVOS = 0x2F
    LC_VERSION_MIN_WATCHOS = 0x30
    LC_NOTE = 0x31
    LC_BUILD_VERSION = 0x32
    LC_DYLD_EXPORTS_TRIE = 0x33 | LC_REQ_DYLD
    LC_DYLD_CHAINED_FIXUPS = 0x34 | LC_REQ_DYLD