import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


def test_basic_reloc_functionality():
    machofile = os.path.join(TEST_BASE, "tests", "armhf", "FileProtection-05.arm64.macho")
    ld = cle.Loader(machofile, auto_load_libs=False)
    assert isinstance(ld.main_object, cle.MachO)
    macho: cle.MachO = ld.main_object
    assert macho.binding_done

    # This is the same data as in test_macho_bindinghelper
    # but this checks that there are actually proper relocs
    expected = {
        0x100009128: "_OBJC_CLASS_$_UIResponder",
        0x1000090F8: "_OBJC_CLASS_$_UIScreen",
        0x100009178: "_OBJC_CLASS_$_UIViewController",
        0x1000090F0: "_OBJC_CLASS_$_UIWindow",
        0x100009150: "_OBJC_METACLASS_$_UIResponder",
        0x1000091A0: "_OBJC_METACLASS_$_UIViewController",
        0x100009148: "_OBJC_METACLASS_$_NSObject",
        0x100009198: "_OBJC_METACLASS_$_NSObject",
        0x100009130: "__objc_empty_cache",
        0x100009158: "__objc_empty_cache",
        0x100009180: "__objc_empty_cache",
        0x1000091A8: "__objc_empty_cache",
        0x1000091D0: "__objc_empty_cache",
        0x1000091F8: "__objc_empty_cache",
        0x1000091D8: "__objc_empty_vtable",
        0x100009200: "__objc_empty_vtable",
        0x100008010: "_class_getName",
        0x100008020: "_objc_allocateClassPair",
        0x100008028: "_objc_copyClassNamesForImage",
        0x100008030: "_objc_getClass",
        0x100008038: "_objc_getMetaClass",
        0x100008040: "_objc_getProtocol",
        0x100008048: "_objc_getRequiredClass",
        0x100008050: "_objc_lookUpClass",
        0x100008058: "_objc_readClassPair",
        0x100008060: "_object_getIndexedIvars",
        0x100008068: "_protocol_getName",
        0x100008000: "__DefaultRuneLocale",
        0x100008008: "___stack_chk_guard",
        0x100008070: "dyld_stub_binder",
        0x1000081F8: "___CFConstantStringClassReference",
        0x100008218: "___CFConstantStringClassReference",
        0x100008238: "___CFConstantStringClassReference",
        0x100008018: "_kCFCoreFoundationVersionNumber",
        0x100008080: "_UIApplicationMain",
        0x100008088: "_NSSearchPathForDirectoriesInDomains",
        0x100008090: "_NSStringFromClass",
        0x100008098: "_class_addMethod",
        0x1000080A0: "_class_addProperty",
        0x1000080A8: "_class_addProtocol",
        0x1000080B0: "_class_getInstanceMethod",
        0x1000080B8: "_class_getInstanceVariable",
        0x1000080C0: "_class_getSuperclass",
        0x1000080C8: "_class_isMetaClass",
        0x1000080D0: "_class_replaceMethod",
        0x1000080D8: "_method_setImplementation",
        0x1000080E0: "_objc_autoreleasePoolPop",
        0x1000080E8: "_objc_autoreleasePoolPush",
        0x1000080F0: "_objc_constructInstance",
        0x1000080F8: "_objc_getClass",
        0x100008100: "_objc_getMetaClass",
        0x100008108: "_objc_getProtocol",
        0x100008110: "_objc_getRequiredClass",
        0x100008118: "_objc_initializeClassPair",
        0x100008120: "_objc_lookUpClass",
        0x100008128: "_objc_msgSend",
        0x100008130: "_objc_msgSendSuper2",
        0x100008138: "_objc_registerClassPair",
        0x100008140: "_objc_setProperty_nonatomic",
        0x100008148: "_object_getClass",
        0x100008150: "_object_getIvar",
        0x100008158: "_property_copyAttributeList",
        0x100008160: "_protocol_getMethodDescription",
        0x100008168: "_sel_getUid",
        0x100008170: "___stack_chk_fail",
        0x100008178: "__dyld_register_func_for_add_image",
        0x100008180: "_asprintf",
        0x100008188: "_bzero",
        0x100008190: "_calloc",
        0x100008198: "_free",
        0x1000081A0: "_hash_create",
        0x1000081A8: "_hash_search",
        0x1000081B0: "_malloc",
        0x1000081B8: "_memcmp",
        0x1000081C0: "_memcpy",
        0x1000081C8: "_pthread_mutex_lock",
        0x1000081D0: "_pthread_mutex_unlock",
        0x1000081D8: "_strcmp",
        0x1000081E0: "_strlen",
        0x1000081E8: "_strncmp",
        0x1000081F0: "_CFStringGetCStringPtr",
    }

    result = {reloc.dest_addr: reloc.resolvedby.name for reloc in macho.relocs}

    assert expected == result


if __name__ == "__main__":
    test_basic_reloc_functionality()
