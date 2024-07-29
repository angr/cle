from __future__ import annotations

import os
from pathlib import Path

import cle
from cle import MachO
from cle.backends.macho.binding import MachOPointerRelocation, MachOSymbolRelocation

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

    result = {
        reloc.rebased_addr: reloc.resolvedby.name for reloc in macho.relocs if isinstance(reloc, MachOSymbolRelocation)
    }

    assert expected == result


def test_chained_fixups_relocs():
    machofile = os.path.join(TEST_BASE, "tests", "aarch64", "dyld_ios15.macho")
    ld = cle.Loader(machofile)
    for reloc in ld.main_object.relocs:
        if not isinstance(reloc, MachOPointerRelocation):
            continue
        mem_val = ld.memory.unpack_word(reloc.rebased_addr)
        # Check that the value at this location is a reasonable pointer
        assert ld.min_addr <= mem_val <= ld.max_addr
        # Check that the reloc was actually applied
        assert ld.memory.unpack_word(reloc.rebased_addr) == reloc.value


ONESIGNAL_BASE = (
    Path(__file__).resolve().parent.parent.parent / "binaries" / "tests" / "aarch64" / "ReverseOneSignal.app"
)


def test_all_relocs():
    """
    This covers all the relocations in the binary, and checks that they are all applied correctly
    This also implicitly tests other things such as correct binding, that the various blobs are parsed, etc
    :return:
    """
    # Expected result was generated via `dyld_info -fixups` on the binary
    expected = """
        __DATA       __got            0x00008000              bind  UIKit/_UIApplicationOpenSettingsURLString
        __DATA       __got            0x00008008              bind  UIKit/_UIBackgroundTaskInvalid
        __DATA       __got            0x00008010              bind  libSystem.B.dylib/__NSConcreteStackBlock
        __DATA       __got            0x00008018              bind  libobjc.A.dylib/___objc_personality_v0
        __DATA       __got            0x00008020              bind  libSystem.B.dylib/___stack_chk_guard
        __DATA       __got            0x00008028              bind  libSystem.B.dylib/__dispatch_main_q
        __DATA       __got            0x00008030              bind  libobjc.A.dylib/_objc_msgSend
        __DATA       __got            0x00008038              bind  libSystem.B.dylib/dyld_stub_binder
        __DATA       __la_symbol_ptr  0x00008040            rebase  0x00006628
        __DATA       __la_symbol_ptr  0x00008040              bind  Foundation/_NSClassFromString
        __DATA       __la_symbol_ptr  0x00008048            rebase  0x00006634
        __DATA       __la_symbol_ptr  0x00008048              bind  Foundation/_NSSelectorFromString
        __DATA       __la_symbol_ptr  0x00008050            rebase  0x000066AC
        __DATA       __la_symbol_ptr  0x00008050              bind  libSystem.B.dylib/__Unwind_Resume
        __DATA       __la_symbol_ptr  0x00008058            rebase  0x000066B8
        __DATA       __la_symbol_ptr  0x00008058              bind  libSystem.B.dylib/___stack_chk_fail
        __DATA       __la_symbol_ptr  0x00008060            rebase  0x000066C4
        __DATA       __la_symbol_ptr  0x00008060              bind  libSystem.B.dylib/_dispatch_after
        __DATA       __la_symbol_ptr  0x00008068            rebase  0x000066D0
        __DATA       __la_symbol_ptr  0x00008068              bind  libSystem.B.dylib/_dispatch_async
        __DATA       __la_symbol_ptr  0x00008070            rebase  0x000066DC
        __DATA       __la_symbol_ptr  0x00008070              bind  libSystem.B.dylib/_dispatch_get_global_queue
        __DATA       __la_symbol_ptr  0x00008078            rebase  0x000066E8
        __DATA       __la_symbol_ptr  0x00008078              bind  libSystem.B.dylib/_dispatch_time
        __DATA       __la_symbol_ptr  0x00008080            rebase  0x000066F4
        __DATA       __la_symbol_ptr  0x00008080              bind  libSystem.B.dylib/_malloc
        __DATA       __la_symbol_ptr  0x00008088            rebase  0x00006640
        __DATA       __la_symbol_ptr  0x00008088              bind  libobjc.A.dylib/_objc_alloc
        __DATA       __la_symbol_ptr  0x00008090            rebase  0x0000664C
        __DATA       __la_symbol_ptr  0x00008090              bind  libobjc.A.dylib/_objc_release
        __DATA       __la_symbol_ptr  0x00008098            rebase  0x00006658
        __DATA       __la_symbol_ptr  0x00008098              bind  libobjc.A.dylib/_objc_retain
        __DATA       __la_symbol_ptr  0x000080A0            rebase  0x00006664
        __DATA       __la_symbol_ptr  0x000080A0              bind  libobjc.A.dylib/_objc_retainAutorelease
        __DATA       __la_symbol_ptr  0x000080A8            rebase  0x00006670
        __DATA       __la_symbol_ptr  0x000080A8              bind  libobjc.A.dylib/_objc_retainAutoreleaseReturnValue
        __DATA       __la_symbol_ptr  0x000080B0            rebase  0x0000667C
        __DATA       __la_symbol_ptr  0x000080B0              bind  libobjc.A.dylib/_objc_retainAutoreleasedReturnValue
        __DATA       __la_symbol_ptr  0x000080B8            rebase  0x00006688
        __DATA       __la_symbol_ptr  0x000080B8              bind  libobjc.A.dylib/_objc_retainBlock
        __DATA       __la_symbol_ptr  0x000080C0            rebase  0x00006694
        __DATA       __la_symbol_ptr  0x000080C0              bind  libobjc.A.dylib/_objc_sync_enter
        __DATA       __la_symbol_ptr  0x000080C8            rebase  0x000066A0
        __DATA       __la_symbol_ptr  0x000080C8              bind  libobjc.A.dylib/_objc_sync_exit
        __DATA       __const          0x000080E0            rebase  0x00007095
        __DATA       __const          0x000080E8            rebase  0x0000757A
        __DATA       __const          0x00008100            rebase  0x00007095
        __DATA       __const          0x00008110              bind  libSystem.B.dylib/__NSConcreteGlobalBlock
        __DATA       __const          0x00008120            rebase  0x000054F4
        __DATA       __const          0x00008128            rebase  0x000080F0
        __DATA       __const          0x00008140            rebase  0x00005D38
        __DATA       __const          0x00008148            rebase  0x00005D40
        __DATA       __const          0x00008150            rebase  0x00007095
        __DATA       __const          0x00008170            rebase  0x00007095
        __DATA       __const          0x00008178            rebase  0x0000757A
        __DATA       __const          0x00008190            rebase  0x0000740F
        __DATA       __const          0x000081A0              bind  libSystem.B.dylib/__NSConcreteGlobalBlock
        __DATA       __const          0x000081B0            rebase  0x00005E2C
        __DATA       __const          0x000081B8            rebase  0x00008180
        __DATA       __cfstring       0x000081C0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000081D0            rebase  0x00007014
        __DATA       __cfstring       0x000081E0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000081F0            rebase  0x00007047
        __DATA       __cfstring       0x00008200              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008210            rebase  0x00007086
        __DATA       __cfstring       0x00008220              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008230            rebase  0x0000709B
        __DATA       __cfstring       0x00008240              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008250            rebase  0x000070AD
        __DATA       __cfstring       0x00008260              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008270            rebase  0x000070EA
        __DATA       __cfstring       0x00008280              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008290            rebase  0x00007116
        __DATA       __cfstring       0x000082A0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000082B0            rebase  0x0000711A
        __DATA       __cfstring       0x000082C0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000082D0            rebase  0x0000711D
        __DATA       __cfstring       0x000082E0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000082F0            rebase  0x0000714A
        __DATA       __cfstring       0x00008300              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008310            rebase  0x00007183
        __DATA       __cfstring       0x00008320              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008330            rebase  0x0000718C
        __DATA       __cfstring       0x00008340              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008350            rebase  0x0000719E
        __DATA       __cfstring       0x00008360              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008370            rebase  0x000071BF
        __DATA       __cfstring       0x00008380              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008390            rebase  0x000071EC
        __DATA       __cfstring       0x000083A0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000083B0            rebase  0x000071F5
        __DATA       __cfstring       0x000083C0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000083D0            rebase  0x00007242
        __DATA       __cfstring       0x000083E0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000083F0            rebase  0x0000725D
        __DATA       __cfstring       0x00008400              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008410            rebase  0x00007261
        __DATA       __cfstring       0x00008420              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008430            rebase  0x00007281
        __DATA       __cfstring       0x00008440              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008450            rebase  0x000072A5
        __DATA       __cfstring       0x00008460              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008470            rebase  0x00007333
        __DATA       __cfstring       0x00008480              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008490            rebase  0x00007389
        __DATA       __cfstring       0x000084A0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000084B0            rebase  0x000073A0
        __DATA       __cfstring       0x000084C0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000084D0            rebase  0x000073FA
        __DATA       __cfstring       0x000084E0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000084F0            rebase  0x00007408
        __DATA       __cfstring       0x00008500              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008510            rebase  0x00007418
        __DATA       __cfstring       0x00008520              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008530            rebase  0x00007444
        __DATA       __cfstring       0x00008540              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008550            rebase  0x00007472
        __DATA       __cfstring       0x00008560              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008570            rebase  0x000074DF
        __DATA       __cfstring       0x00008580              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x00008590            rebase  0x000074EA
        __DATA       __cfstring       0x000085A0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000085B0            rebase  0x0000752C
        __DATA       __cfstring       0x000085C0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000085D0            rebase  0x0000753D
        __DATA       __cfstring       0x000085E0              bind  CoreFoundation/___CFConstantStringClassReference
        __DATA       __cfstring       0x000085F0            rebase  0x00007550
        __DATA       __objc_classlist 0x00008600            rebase  0x00008FE0
        __DATA       __objc_protolist 0x00008608            rebase  0x00009038
        __DATA       __objc_protolist 0x00008610            rebase  0x00009098
        __DATA       __objc_const     0x00008628            rebase  0x00007A5C
        __DATA       __objc_const     0x00008630            rebase  0x00007DC6
        __DATA       __objc_const     0x00008638            rebase  0x00004E58
        __DATA       __objc_const     0x00008640            rebase  0x00007A6E
        __DATA       __objc_const     0x00008648            rebase  0x00007DC6
        __DATA       __objc_const     0x00008650            rebase  0x00004E9C
        __DATA       __objc_const     0x00008658            rebase  0x00007A89
        __DATA       __objc_const     0x00008660            rebase  0x00007DC6
        __DATA       __objc_const     0x00008668            rebase  0x00004EE0
        __DATA       __objc_const     0x00008670            rebase  0x00007A98
        __DATA       __objc_const     0x00008678            rebase  0x00007DCE
        __DATA       __objc_const     0x00008680            rebase  0x00004F5C
        __DATA       __objc_const     0x00008688            rebase  0x00007AA1
        __DATA       __objc_const     0x00008690            rebase  0x00007DD6
        __DATA       __objc_const     0x00008698            rebase  0x00004F60
        __DATA       __objc_const     0x000086A0            rebase  0x00007AA7
        __DATA       __objc_const     0x000086A8            rebase  0x00007DDE
        __DATA       __objc_const     0x000086B0            rebase  0x00004FD0
        __DATA       __objc_const     0x000086B8            rebase  0x00007AB2
        __DATA       __objc_const     0x000086C0            rebase  0x00007DDE
        __DATA       __objc_const     0x000086C8            rebase  0x0000503C
        __DATA       __objc_const     0x000086D0            rebase  0x00007ACF
        __DATA       __objc_const     0x000086D8            rebase  0x00007DD6
        __DATA       __objc_const     0x000086E0            rebase  0x0000510C
        __DATA       __objc_const     0x000086E8            rebase  0x00007AE1
        __DATA       __objc_const     0x000086F0            rebase  0x00007DE9
        __DATA       __objc_const     0x000086F8            rebase  0x00005118
        __DATA       __objc_const     0x00008700            rebase  0x00007B15
        __DATA       __objc_const     0x00008708            rebase  0x00007DF8
        __DATA       __objc_const     0x00008710            rebase  0x00005174
        __DATA       __objc_const     0x00008718            rebase  0x00007B1E
        __DATA       __objc_const     0x00008720            rebase  0x00007E00
        __DATA       __objc_const     0x00008728            rebase  0x000051B8
        __DATA       __objc_const     0x00008730            rebase  0x00007B2B
        __DATA       __objc_const     0x00008738            rebase  0x00007DF8
        __DATA       __objc_const     0x00008740            rebase  0x000051C4
        __DATA       __objc_const     0x00008748            rebase  0x00007B33
        __DATA       __objc_const     0x00008750            rebase  0x00007DD6
        __DATA       __objc_const     0x00008758            rebase  0x000051D0
        __DATA       __objc_const     0x00008760            rebase  0x00007B45
        __DATA       __objc_const     0x00008768            rebase  0x00007E38
        __DATA       __objc_const     0x00008770            rebase  0x00005218
        __DATA       __objc_const     0x00008778            rebase  0x00007B7B
        __DATA       __objc_const     0x00008780            rebase  0x00007DDE
        __DATA       __objc_const     0x00008788            rebase  0x00005358
        __DATA       __objc_const     0x00008790            rebase  0x00007B84
        __DATA       __objc_const     0x00008798            rebase  0x00007DD6
        __DATA       __objc_const     0x000087A0            rebase  0x000054AC
        __DATA       __objc_const     0x000087A8            rebase  0x00007B8E
        __DATA       __objc_const     0x000087B0            rebase  0x00007DD6
        __DATA       __objc_const     0x000087B8            rebase  0x00005500
        __DATA       __objc_const     0x000087C0            rebase  0x00007B96
        __DATA       __objc_const     0x000087C8            rebase  0x00007E4A
        __DATA       __objc_const     0x000087D0            rebase  0x00005554
        __DATA       __objc_const     0x000087D8            rebase  0x00007BB4
        __DATA       __objc_const     0x000087E0            rebase  0x00007DD6
        __DATA       __objc_const     0x000087E8            rebase  0x000056AC
        __DATA       __objc_const     0x000087F0            rebase  0x00007BD5
        __DATA       __objc_const     0x000087F8            rebase  0x00007E55
        __DATA       __objc_const     0x00008800            rebase  0x00005708
        __DATA       __objc_const     0x00008808            rebase  0x00007BFD
        __DATA       __objc_const     0x00008810            rebase  0x00007DD6
        __DATA       __objc_const     0x00008818            rebase  0x00005D48
        __DATA       __objc_const     0x00008820            rebase  0x00007C21
        __DATA       __objc_const     0x00008828            rebase  0x00007DF8
        __DATA       __objc_const     0x00008830            rebase  0x00005EC4
        __DATA       __objc_const     0x00008838            rebase  0x00007957
        __DATA       __objc_const     0x00008840            rebase  0x00007DD6
        __DATA       __objc_const     0x00008848            rebase  0x00005EF0
        __DATA       __objc_const     0x00008850            rebase  0x00007C38
        __DATA       __objc_const     0x00008858            rebase  0x00007DD6
        __DATA       __objc_const     0x00008860            rebase  0x0000636C
        __DATA       __objc_const     0x00008868            rebase  0x00007C47
        __DATA       __objc_const     0x00008870            rebase  0x00007DD6
        __DATA       __objc_const     0x00008878            rebase  0x000063D0
        __DATA       __objc_const     0x00008888            rebase  0x00007C54
        __DATA       __objc_const     0x00008890            rebase  0x00007E63
        __DATA       __objc_const     0x000088A0            rebase  0x00007C5D
        __DATA       __objc_const     0x000088A8            rebase  0x00007DCE
        __DATA       __objc_const     0x000088B8            rebase  0x00007C63
        __DATA       __objc_const     0x000088C0            rebase  0x00007DC6
        __DATA       __objc_const     0x000088D0            rebase  0x00007C68
        __DATA       __objc_const     0x000088D8            rebase  0x00007E6E
        __DATA       __objc_const     0x000088E8            rebase  0x00007C79
        __DATA       __objc_const     0x000088F0            rebase  0x00007E79
        __DATA       __objc_const     0x00008900            rebase  0x00007C95
        __DATA       __objc_const     0x00008908            rebase  0x00007E87
        __DATA       __objc_const     0x00008918            rebase  0x00007CBC
        __DATA       __objc_const     0x00008920            rebase  0x00007DF8
        __DATA       __objc_const     0x00008930            rebase  0x00007CC4
        __DATA       __objc_const     0x00008938            rebase  0x00007E98
        __DATA       __objc_const     0x00008948            rebase  0x00007CD3
        __DATA       __objc_const     0x00008950            rebase  0x00007E98
        __DATA       __objc_const     0x00008960            rebase  0x00007CE4
        __DATA       __objc_const     0x00008968            rebase  0x00007E63
        __DATA       __objc_const     0x00008978            rebase  0x00007CF8
        __DATA       __objc_const     0x00008980            rebase  0x00007EA3
        __DATA       __objc_const     0x00008990            rebase  0x00007D0C
        __DATA       __objc_const     0x00008998            rebase  0x00007DC6
        __DATA       __objc_const     0x000089A8            rebase  0x00007D13
        __DATA       __objc_const     0x000089B0            rebase  0x00007EAE
        __DATA       __objc_const     0x000089C0            rebase  0x00007D1B
        __DATA       __objc_const     0x000089C8            rebase  0x00007DC6
        __DATA       __objc_const     0x000089D8            rebase  0x00007D27
        __DATA       __objc_const     0x000089E0            rebase  0x00007EB7
        __DATA       __objc_const     0x000089F0            rebase  0x00007D33
        __DATA       __objc_const     0x000089F8            rebase  0x00007EBF
        __DATA       __objc_const     0x00008A08            rebase  0x00007D38
        __DATA       __objc_const     0x00008A10            rebase  0x00007EB7
        __DATA       __objc_const     0x00008A20            rebase  0x00007D3D
        __DATA       __objc_const     0x00008A28            rebase  0x00007DCE
        __DATA       __objc_const     0x00008A38            rebase  0x00007D48
        __DATA       __objc_const     0x00008A40            rebase  0x00007DC6
        __DATA       __objc_const     0x00008A58            rebase  0x00007D54
        __DATA       __objc_const     0x00008A60            rebase  0x00007DC6
        __DATA       __objc_const     0x00008A78            rebase  0x00007D38
        __DATA       __objc_const     0x00008A80            rebase  0x00007D65
        __DATA       __objc_const     0x00008A88            rebase  0x00007D3D
        __DATA       __objc_const     0x00008A90            rebase  0x00007D6A
        __DATA       __objc_const     0x00008A98            rebase  0x00007D48
        __DATA       __objc_const     0x00008AA0            rebase  0x00007D6F
        __DATA       __objc_const     0x00008AA8            rebase  0x00007D54
        __DATA       __objc_const     0x00008AB0            rebase  0x00007D6F
        __DATA       __objc_const     0x00008AB8            rebase  0x00007E63
        __DATA       __objc_const     0x00008AC0            rebase  0x00007DCE
        __DATA       __objc_const     0x00008AC8            rebase  0x00007DC6
        __DATA       __objc_const     0x00008AD0            rebase  0x00007E6E
        __DATA       __objc_const     0x00008AD8            rebase  0x00007E79
        __DATA       __objc_const     0x00008AE0            rebase  0x00007E87
        __DATA       __objc_const     0x00008AE8            rebase  0x00007DF8
        __DATA       __objc_const     0x00008AF0            rebase  0x00007E98
        __DATA       __objc_const     0x00008AF8            rebase  0x00007E98
        __DATA       __objc_const     0x00008B00            rebase  0x00007ED1
        __DATA       __objc_const     0x00008B08            rebase  0x00007EA3
        __DATA       __objc_const     0x00008B10            rebase  0x00007DC6
        __DATA       __objc_const     0x00008B18            rebase  0x00007EAE
        __DATA       __objc_const     0x00008B20            rebase  0x00007DC6
        __DATA       __objc_const     0x00008B28            rebase  0x00007EB7
        __DATA       __objc_const     0x00008B30            rebase  0x00007EBF
        __DATA       __objc_const     0x00008B38            rebase  0x00007EB7
        __DATA       __objc_const     0x00008B40            rebase  0x00007DCE
        __DATA       __objc_const     0x00008B48            rebase  0x00007EE6
        __DATA       __objc_const     0x00008B50            rebase  0x00007EE6
        __DATA       __objc_const     0x00008B60            rebase  0x00009038
        __DATA       __objc_const     0x00008B78            rebase  0x00007ACF
        __DATA       __objc_const     0x00008B80            rebase  0x00007DD6
        __DATA       __objc_const     0x00008B90            rebase  0x00007AA7
        __DATA       __objc_const     0x00008B98            rebase  0x00007DDE
        __DATA       __objc_const     0x00008BA8            rebase  0x00007B15
        __DATA       __objc_const     0x00008BB0            rebase  0x00007DF8
        __DATA       __objc_const     0x00008BC0            rebase  0x00007DD6
        __DATA       __objc_const     0x00008BC8            rebase  0x00007DDE
        __DATA       __objc_const     0x00008BD0            rebase  0x00007DF8
        __DATA       __objc_const     0x00008BE0            rebase  0x00009098
        __DATA       __objc_const     0x00008C08            rebase  0x0000757B
        __DATA       __objc_const     0x00008C10            rebase  0x00008620
        __DATA       __objc_const     0x00008C18            rebase  0x00008BD8
        __DATA       __objc_const     0x00008C40            rebase  0x00007D80
        __DATA       __objc_const     0x00008C48            rebase  0x00007EF8
        __DATA       __objc_const     0x00008C50            rebase  0x00005FD4
        __DATA       __objc_const     0x00008C58            rebase  0x00007DA4
        __DATA       __objc_const     0x00008C60            rebase  0x00007EF8
        __DATA       __objc_const     0x00008C68            rebase  0x000062D8
        __DATA       __objc_const     0x00008C78            rebase  0x00007D38
        __DATA       __objc_const     0x00008C80            rebase  0x00007D65
        __DATA       __objc_const     0x00008C88            rebase  0x00007D3D
        __DATA       __objc_const     0x00008C90            rebase  0x00007D6A
        __DATA       __objc_const     0x00008C98            rebase  0x00007D48
        __DATA       __objc_const     0x00008CA0            rebase  0x00007D6F
        __DATA       __objc_const     0x00008CA8            rebase  0x00007D54
        __DATA       __objc_const     0x00008CB0            rebase  0x00007D6F
        __DATA       __objc_const     0x00008CD0            rebase  0x0000757B
        __DATA       __objc_const     0x00008CD8            rebase  0x00008C38
        __DATA       __objc_const     0x00008CE0            rebase  0x00008BD8
        __DATA       __objc_const     0x00008CF8            rebase  0x00008C70
        __DATA       __objc_selrefs   0x00008D00            rebase  0x00007864
        __DATA       __objc_selrefs   0x00008D08            rebase  0x0000778A
        __DATA       __objc_selrefs   0x00008D10            rebase  0x00007666
        __DATA       __objc_selrefs   0x00008D18            rebase  0x000077A0
        __DATA       __objc_selrefs   0x00008D20            rebase  0x0000771A
        __DATA       __objc_selrefs   0x00008D28            rebase  0x00007967
        __DATA       __objc_selrefs   0x00008D30            rebase  0x00007C21
        __DATA       __objc_selrefs   0x00008D38            rebase  0x000077B2
        __DATA       __objc_selrefs   0x00008D40            rebase  0x00007B84
        __DATA       __objc_selrefs   0x00008D48            rebase  0x00007C5D
        __DATA       __objc_selrefs   0x00008D50            rebase  0x00007B33
        __DATA       __objc_selrefs   0x00008D58            rebase  0x00007676
        __DATA       __objc_selrefs   0x00008D60            rebase  0x0000785E
        __DATA       __objc_selrefs   0x00008D68            rebase  0x000076FA
        __DATA       __objc_selrefs   0x00008D70            rebase  0x0000760E
        __DATA       __objc_selrefs   0x00008D78            rebase  0x00007B8E
        __DATA       __objc_selrefs   0x00008D80            rebase  0x0000766C
        __DATA       __objc_selrefs   0x00008D88            rebase  0x0000794E
        __DATA       __objc_selrefs   0x00008D90            rebase  0x00007B45
        __DATA       __objc_selrefs   0x00008D98            rebase  0x000075B4
        __DATA       __objc_selrefs   0x00008DA0            rebase  0x00007820
        __DATA       __objc_selrefs   0x00008DA8            rebase  0x00007760
        __DATA       __objc_selrefs   0x00008DB0            rebase  0x000078DA
        __DATA       __objc_selrefs   0x00008DB8            rebase  0x00007BD5
        __DATA       __objc_selrefs   0x00008DC0            rebase  0x0000770E
        __DATA       __objc_selrefs   0x00008DC8            rebase  0x000077EE
        __DATA       __objc_selrefs   0x00008DD0            rebase  0x00007706
        __DATA       __objc_selrefs   0x00008DD8            rebase  0x00007686
        __DATA       __objc_selrefs   0x00008DE0            rebase  0x0000783C
        __DATA       __objc_selrefs   0x00008DE8            rebase  0x00007B15
        __DATA       __objc_selrefs   0x00008DF0            rebase  0x000075A8
        __DATA       __objc_selrefs   0x00008DF8            rebase  0x00007A5C
        __DATA       __objc_selrefs   0x00008E00            rebase  0x0000797B
        __DATA       __objc_selrefs   0x00008E08            rebase  0x000076EE
        __DATA       __objc_selrefs   0x00008E10            rebase  0x00007A6E
        __DATA       __objc_selrefs   0x00008E18            rebase  0x00007766
        __DATA       __objc_selrefs   0x00008E20            rebase  0x000076A6
        __DATA       __objc_selrefs   0x00008E28            rebase  0x0000784E
        __DATA       __objc_selrefs   0x00008E30            rebase  0x00007732
        __DATA       __objc_selrefs   0x00008E38            rebase  0x000075F8
        __DATA       __objc_selrefs   0x00008E40            rebase  0x00007796
        __DATA       __objc_selrefs   0x00008E48            rebase  0x00007C68
        __DATA       __objc_selrefs   0x00008E50            rebase  0x00007888
        __DATA       __objc_selrefs   0x00008E58            rebase  0x00007AE1
        __DATA       __objc_selrefs   0x00008E60            rebase  0x00007874
        __DATA       __objc_selrefs   0x00008E68            rebase  0x000077DC
        __DATA       __objc_selrefs   0x00008E70            rebase  0x00007957
        __DATA       __objc_selrefs   0x00008E78            rebase  0x00007993
        __DATA       __objc_selrefs   0x00008E80            rebase  0x00007622
        __DATA       __objc_selrefs   0x00008E88            rebase  0x00007C38
        __DATA       __objc_selrefs   0x00008E90            rebase  0x000076B6
        __DATA       __objc_selrefs   0x00008E98            rebase  0x0000790C
        __DATA       __objc_selrefs   0x00008EA0            rebase  0x00007B96
        __DATA       __objc_selrefs   0x00008EA8            rebase  0x00007BB4
        __DATA       __objc_selrefs   0x00008EB0            rebase  0x00007C47
        __DATA       __objc_selrefs   0x00008EB8            rebase  0x000076CA
        __DATA       __objc_selrefs   0x00008EC0            rebase  0x000078FE
        __DATA       __objc_selrefs   0x00008EC8            rebase  0x00007830
        __DATA       __objc_selrefs   0x00008ED0            rebase  0x0000776A
        __DATA       __objc_selrefs   0x00008ED8            rebase  0x0000763E
        __DATA       __objc_selrefs   0x00008EE0            rebase  0x0000780E
        __DATA       __objc_selrefs   0x00008EE8            rebase  0x00007A89
        __DATA       __objc_selrefs   0x00008EF0            rebase  0x000075C4
        __DATA       __objc_selrefs   0x00008EF8            rebase  0x00007BFD
        __DATA       __objc_selrefs   0x00008F00            rebase  0x000079C7
        __DATA       __objc_selrefs   0x00008F08            rebase  0x00007AB2
        __DATA       __objc_selrefs   0x00008F10            rebase  0x000079F4
        __DATA       __objc_selrefs   0x00008F18            rebase  0x000079B1
        __DATA       __objc_selrefs   0x00008F20            rebase  0x00007B2B
        __DATA       __objc_selrefs   0x00008F28            rebase  0x00007A33
        __DATA       __objc_selrefs   0x00008F30            rebase  0x00007A1E
        __DATA       __objc_selrefs   0x00008F38            rebase  0x0000774E
        __DATA       __objc_selrefs   0x00008F40            rebase  0x00007650
        __DATA       __objc_selrefs   0x00008F48            rebase  0x0000777C
        __DATA       __objc_classrefs 0x00008F50              bind  CoreFoundation/_OBJC_CLASS_$_NSMutableArray
        __DATA       __objc_classrefs 0x00008F58              bind  libobjc.A.dylib/_OBJC_CLASS_$_NSObject
        __DATA       __objc_classrefs 0x00008F60            rebase  0x00008FE0
        __DATA       __objc_classrefs 0x00008F68              bind  OneSignalCore/_OBJC_CLASS_$_OneSignalConfigManager
        __DATA       __objc_classrefs 0x00008F70              bind  OneSignalCore/_OBJC_CLASS_$_OSRemoteParamController
        __DATA       __objc_classrefs 0x00008F78              bind  OneSignalCore/_OBJC_CLASS_$_OneSignalLog
        __DATA       __objc_classrefs 0x00008F80              bind  Foundation/_OBJC_CLASS_$_NSString
        __DATA       __objc_classrefs 0x00008F88            bind  OneSignalCore/_OBJC_CLASS_$_OSPrivacyConsentController
        __DATA       __objc_classrefs 0x00008F90              bind  CoreFoundation/_OBJC_CLASS_$_NSTimer
        __DATA       __objc_classrefs 0x00008F98              bind  UIKit/_OBJC_CLASS_$_UIApplication
        __DATA       __objc_classrefs 0x00008FA0              bind  Foundation/_OBJC_CLASS_$_NSBundle
        __DATA       __objc_classrefs 0x00008FA8              bind  OneSignalCore/_OBJC_CLASS_$_OSDeviceUtils
        __DATA       __objc_classrefs 0x00008FB0              bind  Foundation/_OBJC_CLASS_$_NSNumber
        __DATA       __objc_classrefs 0x00008FB8              bind  OneSignalCore/_OBJC_CLASS_$_OSDialogInstanceManager
        __DATA       __objc_classrefs 0x00008FC0              bind  CoreFoundation/_OBJC_CLASS_$_NSArray
        __DATA       __objc_classrefs 0x00008FC8              bind  CoreFoundation/_OBJC_CLASS_$_NSURL
        __DATA       __objc_classrefs 0x00008FD0              bind  CoreFoundation/_OBJC_CLASS_$_NSInvocation
    __DATA __objc_classrefs 0x00008FD8  bind  OneSignalUser/_OBJC_CLASS_$__TtC13OneSignalUser24OneSignalUserManagerImpl
        __DATA       __objc_data      0x00008FE0            rebase  0x00009008
        __DATA       __objc_data      0x00008FE8              bind  libobjc.A.dylib/_OBJC_CLASS_$_NSObject
        __DATA       __objc_data      0x00008FF0              bind  libobjc.A.dylib/__objc_empty_cache
        __DATA       __objc_data      0x00009000            rebase  0x00008CB8
        __DATA       __objc_data      0x00009008              bind  libobjc.A.dylib/_OBJC_METACLASS_$_NSObject
        __DATA       __objc_data      0x00009010              bind  libobjc.A.dylib/_OBJC_METACLASS_$_NSObject
        __DATA       __objc_data      0x00009018              bind  libobjc.A.dylib/__objc_empty_cache
        __DATA       __objc_data      0x00009028            rebase  0x00008BF0
        __DATA       __data           0x00009040            rebase  0x0000759F
        __DATA       __data           0x00009050            rebase  0x00008880
        __DATA       __data           0x00009060            rebase  0x00008A50
        __DATA       __data           0x00009070            rebase  0x00008A70
        __DATA       __data           0x00009080            rebase  0x00008AB8
        __DATA       __data           0x000090A0            rebase  0x00007594
        __DATA       __data           0x000090A8            rebase  0x00008B58
        __DATA       __data           0x000090B8            rebase  0x00008B70
        __DATA       __data           0x000090E0            rebase  0x00008BC0
    """

    ld = cle.Loader(
        ONESIGNAL_BASE / "Frameworks" / "OneSignalLocation.framework" / "OneSignalLocation",
        main_opts={"base_addr": 0x1_0000_0000},
    )
    lib = ld.main_object
    assert isinstance(lib, MachO)

    for line in expected.split("\n"):
        if not line.strip():
            continue
        _segment, _section, address, ty, target = line.split()
        address = int(address, 16)

        if ty == "bind":
            sym_reloc: MachOSymbolRelocation
            [sym_reloc] = [
                r for r in ld.main_object.relocs if r.relative_addr == address and isinstance(r, MachOSymbolRelocation)
            ]

            _library, symbol_name = target.split("/")
            assert sym_reloc.symbol.name == symbol_name
        elif ty == "rebase":
            ptr_reloc: MachOPointerRelocation
            [ptr_reloc] = [
                r for r in ld.main_object.relocs if r.relative_addr == address and isinstance(r, MachOPointerRelocation)
            ]

            target_addr = int(target, 16)
            assert ptr_reloc.data == target_addr


if __name__ == "__main__":
    test_basic_reloc_functionality()
    test_chained_fixups_relocs()
