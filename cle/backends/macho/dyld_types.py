from collections import OrderedDict

import angr
from angr.sim_type import SimStruct, SimTypeNum, SimTypeNumOffset


def setup_types():
    angr.types.register_types(angr.types.parse_types("""
    struct dyld_chained_fixups_header
    {
        uint32_t    fixups_version;    /* 0 */
        uint32_t    starts_offset;     /* offset of dyld_chained_starts_in_image in chain_data */
        uint32_t    imports_offset;    /* offset of imports table in chain_data */
        uint32_t    symbols_offset;    /* offset of symbol strings in chain_data */
        uint32_t    imports_count;     /* number of imported symbol names */
        uint32_t    imports_format;    /* DYLD_CHAINED_IMPORT* */
        uint32_t    symbols_format;    /* 0 => uncompressed, 1 => zlib compressed */
    };

    struct build_version_command {
        uint32_t    cmd;        /* LC_BUILD_VERSION */
        uint32_t    cmdsize;    /* sizeof(struct build_version_command) plus */
        /* ntools * sizeof(struct build_tool_version) */
        uint32_t    platform;   /* platform */
        uint32_t    minos;      /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
        uint32_t    sdk;        /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
        uint32_t    ntools;     /* number of tool entries following this */
    };
    
    """))

    dyld_chained_import = SimStruct(name="dyld_chained_import", pack=True, fields=OrderedDict([
                ("lib_ordinal", SimTypeNumOffset(8, signed=False)),
                ("weak_import", SimTypeNumOffset(1, signed=False)),
                ("name_offset", SimTypeNumOffset(23, signed=False))
            ]))

    angr.types.register_types(dyld_chained_import)

    dyld_chained_starts_in_image = SimStruct(name="dyld_chained_starts_in_image", fields=OrderedDict([
        ("seg_count", SimTypeNum(32, signed=False)),
        ("seg_info_offset", SimTypeNum(32, signed=False))
    ]))
    angr.types.register_types(dyld_chained_starts_in_image)

    dyld_chained_starts_in_segment = SimStruct(name="dyld_chained_starts_in_segment", fields=OrderedDict([
        ("size", SimTypeNum(32, signed=False)),
        ("page_size", SimTypeNum(16, signed=False)),
        ("pointer_format", SimTypeNum(16, signed=False)),
        ("segment_offset", SimTypeNum(64, signed=False)),
        ("max_valid_pointer", SimTypeNum(32, signed=False)),
        ("page_count", SimTypeNum(16, signed=False)),
        ("page_start", SimTypeNum(16, signed=False))
    ]))

    angr.types.register_types(dyld_chained_starts_in_segment)

    dyld_chained_ptr_64_rebase = angr.types.parse_type("""struct dyld_chained_ptr_64_rebase
{
    uint64_t    target    : 36,    /* 64GB max image size (DYLD_CHAINED_PTR_64 => vmAddr, DYLD_CHAINED_PTR_64_OFFSET => runtimeOffset) */
                high8     :  8,    /* top 8 bits set to this (DYLD_CHAINED_PTR_64 => after slide added, DYLD_CHAINED_PTR_64_OFFSET => before slide added) */
                reserved  :  7,    /* all zeros */
                next      : 12,    /* 4-byte stride */
                bind      :  1;    /* == 0 */
}""")

    angr.types.register_types(dyld_chained_ptr_64_rebase)

    dyld_chained_ptr_64_bind = SimStruct(name="dyld_chained_ptr_64_bind", pack=True, fields=OrderedDict([
        ("ordinal", SimTypeNumOffset(24, signed=False)),
        ("addend", SimTypeNumOffset(8, signed=False)),
        ("reserved", SimTypeNumOffset(19, signed=False)),
        ("next", SimTypeNumOffset(12, signed=False)),
        ("bind", SimTypeNumOffset(1, signed=False))
    ]))
    angr.types.register_types(dyld_chained_ptr_64_bind)
