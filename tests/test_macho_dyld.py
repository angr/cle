import unittest
from pathlib import Path
from typing import cast

import cle
from cle import MachO

TEST_BASE = Path(__file__).resolve().parent.parent.parent / "binaries"


class TestMachODyld(unittest.TestCase):
    def test_fixups(self):
        """
        Tests the pointer format DYLD_CHAINED_PTR_64_OFFSET
        :return:
        """
        binary: MachO = cast(MachO,
                            cle.Loader(str(TEST_BASE / "tests" / "aarch64" / "dyld_ios15.macho"))
                            .main_object)
        expected = {0x100008100: 0x100007a40,
                    0x1000081e0: 0x1000072b0,
                    0x1000081e8: 0x1000072dc,
                    0x1000081f0: 0x1000072e4,
                    0x1000081f8: 0x100007310,
                    0x100008200: 0x100007350,
                    0x100008208: 0x10000735c,
                    0x100008210: 0x10000738c,
                    0x100008218: 0x1000073e8,
                    0x100008238: 0x1000081e0,
                    0x100008248: 0x100007a40,
                    0x1000082a0: 0x100007afc,
                    0x1000082d8: 0x10000c0e8,
                    0x10000c018: 0x100007b90,
                    0x10000c060: 0x100007b90,
                    0x10000c068: 0x100007998,
                    0x10000c090: 0x100007c2a,
                    0x10000c0d0: 0x10000c000,
                    0x10000c0d8: 0x100007210,
                    0x10000c0e8: 0x10000c0b0,
                    0x10000c108: 0x10000c04a,
                    0x10000c128: 0x1000079f0}

        self.assertEqual(len(binary._dyld_rebases), len(expected))
        self.assertDictEqual(binary._dyld_rebases, expected)


    def test_symbols(self):
        l = cle.Loader(str(TEST_BASE / "tests" / "aarch64" / "dyld_ios15.macho"))
        binary: MachO = cast(MachO, l.main_object)

        expected = [(0x100008000, '_$s10Foundation5NSLogyySS_s7CVarArg_pdtF'),
                    (0x100008008,
                    '_$s2os0A4_log_3dso0B04type_ys12StaticStringV_SVSgSo03OS_a1_B0CSo0a1_b1_D2_tas7CVarArg_pdtF'),
                    (0x100008010, '_$s7SwiftUI11WindowGroupV7contentACyxGxyXE_tcfC'),
                    (0x100008018, '_$s7SwiftUI11WindowGroupVMn'),
                    (0x100008020, '_$s7SwiftUI11WindowGroupVyxGAA5SceneAAMc'),
                    (0x100008028, '_$s7SwiftUI12SceneBuilderV10buildBlockyxxAA0C0RzlFZ'),
                    (0x100008030, '_$s7SwiftUI13_VStackLayoutVMn'),
                    (0x100008038, '_$s7SwiftUI13_VariadicViewO4TreeVMn'),
                    (0x100008040, '_$s7SwiftUI14_PaddingLayoutVMn'),
                    (0x100008048, '_$s7SwiftUI15ModifiedContentVMn'),
                    (0x100008050, '_$s7SwiftUI18LocalizedStringKeyV13stringLiteralACSS_tcfC'),
                    (0x100008058, '_$s7SwiftUI19HorizontalAlignmentV6centerACvgZ'),
                    (0x100008060, '_$s7SwiftUI3AppPAAE4mainyyFZ'),
                    (0x100008068, '_$s7SwiftUI4EdgeO3SetV3allAEvgZ'),
                    (0x100008070, '_$s7SwiftUI4TextVMn'),
                    (0x100008078,
                    '_$s7SwiftUI4ViewPAAE05_makeC04view6inputsAA01_C7OutputsVAA11_GraphValueVyxG_AA01_C6InputsVtFZ'),
                    (0x100008080,
                    '_$s7SwiftUI4ViewPAAE05_makeC4List4view6inputsAA01_cE7OutputsVAA11_GraphValueVyxG_AA01_cE6InputsVtFZ'),
                    (0x100008088, '_$s7SwiftUI4ViewPAAE14_viewListCount6inputsSiSgAA01_ceF6InputsV_tFZ'),
                    (0x100008090, '_$s7SwiftUI5StateV12wrappedValueACyxGx_tcfC'),
                    (0x100008098, '_$s7SwiftUI5StateVMn'),
                    (0x1000080a0, '_$s7SwiftUI6ButtonVA2A4TextVRszrlE_6actionACyAEGAA18LocalizedStringKeyV_yyctcfC'),
                    (0x1000080a8, '_$s7SwiftUI6ButtonVMn'),
                    (0x1000080b0, '_$s7SwiftUI6VStackVMn'),
                    (0x1000080b8, '_$s7SwiftUI6VStackVyxGAA4ViewAAMc'),
                    (0x1000080c0, '_$sSiN'),
                    (0x1000080c8, '_$sSo13os_log_type_ta0A0E7defaultABvgZ'),
                    (0x1000080d0, '_$sSo8NSObjectCs7CVarArg10ObjectiveCMc'),
                    (0x1000080d8, '_$sSo8NSStringC10FoundationE13stringLiteralABs12StaticStringV_tcfC'),
                    (0x1000080e0, '_$sSo9OS_os_logC0B0E7defaultABvgZ'),
                    (0x1000080e8, '_$ss23_ContiguousArrayStorageCMn'),
                    (0x1000080f0, '_$ss7CVarArgMp'),
                    (0x1000080f8, '___chkstk_darwin'),
                    (0x100008108, '__swiftEmptyArrayStorage'),
                    (0x100008110, '_objc_opt_self'),
                    (0x100008118, '_objc_release'),
                    (0x100008120, '_swift_allocObject'),
                    (0x100008128, '_swift_deallocClassInstance'),
                    (0x100008130, '_swift_getObjCClassMetadata'),
                    (0x100008138, '_swift_getOpaqueTypeConformance'),
                    (0x100008140, '_swift_getTypeByMangledNameInContext'),
                    (0x100008148, '_swift_getTypeByMangledNameInContextInMetadataState'),
                    (0x100008150, '_swift_getWitnessTable'),
                    (0x100008158, '_swift_release'),
                    (0x100008160, '_swift_retain'),
                    (0x100008168, '__swift_FORCE_LOAD_$_swiftObjectiveC'),
                    (0x100008170, '__swift_FORCE_LOAD_$_swiftDarwin'),
                    (0x100008178, '__swift_FORCE_LOAD_$_swiftos'),
                    (0x100008180, '__swift_FORCE_LOAD_$_swiftUniformTypeIdentifiers'),
                    (0x100008188, '__swift_FORCE_LOAD_$_swiftFoundation'),
                    (0x100008190, '__swift_FORCE_LOAD_$_swiftCoreFoundation'),
                    (0x100008198, '__swift_FORCE_LOAD_$_swiftDispatch'),
                    (0x1000081a0, '__swift_FORCE_LOAD_$_swiftCoreGraphics'),
                    (0x1000081a8, '__swift_FORCE_LOAD_$_swiftUIKit'),
                    (0x1000081b0, '__swift_FORCE_LOAD_$_swiftCoreImage'),
                    (0x1000081b8, '__swift_FORCE_LOAD_$_swiftMetal'),
                    (0x1000081c0, '__swift_FORCE_LOAD_$_swiftQuartzCore'),
                    (0x1000081c8, '__swift_FORCE_LOAD_$_swiftFileProvider'),
                    (0x1000081d0, '__swift_FORCE_LOAD_$_swiftDataDetection'),
                    (0x1000081d8, '__swift_FORCE_LOAD_$_swiftCoreData'),
                    (0x100008258, '_$s7SwiftUI4ViewMp'),
                    (0x100008260, '_$s7SwiftUI4ViewP4BodyAC_AaBTn'),
                    (0x100008268, '_$s4Body7SwiftUI4ViewPTl'),
                    (0x100008270,
                    '_$s7SwiftUI4ViewP05_makeC04view6inputsAA01_C7OutputsVAA11_GraphValueVyxG_AA01_C6InputsVtFZTq'),
                    (0x100008278,
                    '_$s7SwiftUI4ViewP05_makeC4List4view6inputsAA01_cE7OutputsVAA11_GraphValueVyxG_AA01_cE6InputsVtFZTq'),
                    (0x100008280, '_$s7SwiftUI4ViewP14_viewListCount6inputsSiSgAA01_ceF6InputsV_tFZTq'),
                    (0x100008288, '_$s7SwiftUI4ViewP4body4BodyQzvgTq'),
                    (0x100008290, '_$sytWV'),
                    (0x1000082a8, '_$s7SwiftUI3AppMp'),
                    (0x1000082b0, '_$s7SwiftUI3AppP4BodyAC_AA5SceneTn'),
                    (0x1000082b8, '_$s4Body7SwiftUI3AppPTl'),
                    (0x1000082c0, '_$s7SwiftUI3AppP4body4BodyQzvgTq'),
                    (0x1000082c8, '_$s7SwiftUI3AppPxycfCTq'),
                    (0x1000082d0, '_$s7SwiftUI5SceneMp'),
                    (0x10000c098, '_OBJC_CLASS_$_OS_os_log'),
                    (0x10000c0a0, '_OBJC_CLASS_$_NSString'),
                    (0x10000c0b0, '_OBJC_METACLASS_$__TtCs12_SwiftObject'),
                    (0x10000c0b8, '_OBJC_METACLASS_$__TtCs12_SwiftObject'),
                    (0x10000c0c0, '__objc_empty_cache'),
                    (0x10000c0e0, '_$sBoWV'),
                    (0x10000c0f0, '_OBJC_CLASS_$__TtCs12_SwiftObject'),
                    (0x10000c0f8, '__objc_empty_cache'),
                    (0x10000c138, '_swift_deletedMethodError'),
                    (0x10000c140, '_swift_deletedMethodError')]
        result = [(r.dest_addr, r.resolvedby.name) for r in binary.relocs]
        self.assertListEqual(expected, result)


if __name__ == '__main__':
    unittest.main()
