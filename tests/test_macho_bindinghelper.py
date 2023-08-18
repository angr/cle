# Contributed September 2019 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).
import os
import unittest

import cle
from cle import CLEInvalidBinaryError, MachO
from cle.backends.macho.binding import (
    BindingState,
    n_opcode_done,
    n_opcode_set_addend_sleb,
    n_opcode_set_dylib_ordinal_imm,
    n_opcode_set_dylib_ordinal_uleb,
    n_opcode_set_dylib_special_imm,
    n_opcode_set_trailing_flags_imm,
    n_opcode_set_type_imm,
    read_sleb,
    read_uleb,
)

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


class TestBindingState(unittest.TestCase):
    def setUp(self):
        self.uut_64 = BindingState(True)
        self.uut_32 = BindingState(False)

    def test_init_64(self):
        """Ensure that initialization works properly for 64 bit
        Assertions taken from ImageLoaderMachOCompressed.cpp, start of eachBind
        """
        self.assertEqual(self.uut_64.segment_index, 0)
        self.assertEqual(self.uut_64.address, 0)
        self.assertEqual(self.uut_64.sym_flags, 0)
        self.assertEqual(self.uut_64.sym_name, "")
        self.assertEqual(self.uut_64.lib_ord, 0)
        self.assertEqual(self.uut_64.addend, 0)
        self.assertEqual(self.uut_64.done, False)

    def test_init_32(self):
        """Ensure that initialization works properly for 32 bit
        Assertions taken from ImageLoaderMachOCompressed.cpp, start of eachBind
        """
        self.assertEqual(self.uut_32.segment_index, 0)
        self.assertEqual(self.uut_32.address, 0)
        self.assertEqual(self.uut_32.sym_flags, 0)
        self.assertEqual(self.uut_32.sym_name, "")
        self.assertEqual(self.uut_32.lib_ord, 0)
        self.assertEqual(self.uut_32.addend, 0)
        self.assertEqual(self.uut_32.done, False)

    def test_add_address_ov_32(self):
        """Ensure proper updating of address and wraparound (32bits)"""
        self.skipTest(
            "TODO test_add_address_ov_32: add_address_ov does not consider the 64 bit flag and does not change the "
            "size of uintptr_t to 2**32 so calculation will fail"
        )

        self.uut_32.add_address_ov(10000, 10000)
        self.assertEqual(self.uut_32.address, 20000)

        self.uut_32.add_address_ov(699999999, 10000000)
        self.assertEqual(self.uut_32.address, 709999999)

        self.uut_32.add_address_ov(4294967295, 10000)
        self.assertEqual(self.uut_32.address, 9999)

        self.uut_32.add_address_ov(3294967295, 1000100000)
        self.assertEqual(self.uut_32.address, 99999)

        # TODO test_add_address_ov_32: we do probably do not expect negative numbers as second argument,
        # but then the address will be negative... and it does not wrap around. Test is commented out.
        self.uut_32.add_address_ov(10000, -10000)
        self.assertEqual(self.uut_32.address, 0)

        self.uut_32.add_address_ov(10000, -100000)
        self.assertEqual(self.uut_32.address, 4294877296)

    def test_add_address_ov_64(self):
        """Ensure proper updating of address and wraparound (64bits)"""
        self.uut_64.add_address_ov(10000, 10000)
        self.assertEqual(self.uut_64.address, 20000)

        self.uut_64.add_address_ov(0, 0)
        self.assertEqual(self.uut_64.address, 0)

        self.uut_64.add_address_ov(699999999999, 10000000000)
        self.assertEqual(self.uut_64.address, 709999999999)

        self.uut_64.add_address_ov(1844674407370955160, 10000000000)
        self.assertEqual(self.uut_64.address, 1844674417370955160)

        self.uut_64.add_address_ov(17000000000000000000, 1900000000000000000)
        self.assertEqual(self.uut_64.address, 453255926290448384)

        # TODO test_add_address_ov_64: we do probably do not expect negative numbers as second argument,
        # but then the address will be negative... and it does not wrap around. Test is commented out.
        # self.uut_64.add_address_ov(123456, -10000000000)
        # self.assertEqual(self.uut_64.address, 18446744063709551616)

        self.uut_64.add_address_ov(1000, -1000)
        self.assertEqual(self.uut_64.address, 0)

    def test_check_address_bounds(self):
        """Ensure that exception gets thrown under the right circumstances"""
        self.uut_64 = BindingState(True)

        # TODO test_check_address_bounds: Why does this raise an exception?
        # address and seg_end address are not 0 when entering the function
        # self.uut_64.address = 0
        # self.uut_64.seg_end_address = 0
        # self.uut_64.check_address_bounds()

        self.uut_64 = BindingState(True)
        self.uut_64.address = 0
        self.uut_64.seg_end_address = 1
        self.uut_64.check_address_bounds()

        self.uut_64 = BindingState(True)
        self.uut_64.address = 10000
        self.uut_64.seg_end_address = 10
        with self.assertRaises(CLEInvalidBinaryError):
            self.uut_64.check_address_bounds()

        self.uut_64 = BindingState(True)
        self.uut_64.address = -10000
        self.uut_64.seg_end_address = -100000
        with self.assertRaises(CLEInvalidBinaryError):
            self.uut_64.check_address_bounds()


class TestLEB(unittest.TestCase):
    def test_read_uleb(self):
        # Test vector from wikipedia https://en.wikipedia.org/wiki/LEB128
        buffer = b"\xE5\x8E\x26"
        expected = (624485, 3)
        result = read_uleb(buffer, 0)
        self.assertEqual(expected, result)

    def test_read_sleb(self):
        # Test vector from wikipedia https://en.wikipedia.org/wiki/LEB128
        buffer = b"\xE5\x8E\x26"
        expected = (624485, 3)
        result = read_sleb(buffer, 0)
        self.assertEqual(expected, result)

        buffer = b"\x9b\xf1\x59"
        result = read_sleb(buffer, 0)
        expected = (-624485, 3)
        self.assertEqual(result, expected)


# noinspection PyTypeChecker
class TestBindingHelper(unittest.TestCase):
    # Note: These tests will require mocking MachOBinary objects

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_do_normal_bind(self):
        self.skipTest("TODO")  # implement this after all submethods are tested for a complete run
        # the test data should exercise each case at least once and ensure that submethods interact
        # well i.e. that the aggregation produces correct results

    def test_do_lazy_bind(self):
        self.skipTest("TODO")  # implement this after all submethods are tested for a complete run
        # the test data should exercise each case at least once and ensure that submethods interact
        # well i.e. that the aggregation produces correct results

    # the format is def X(state,binary,immediate,blob) => state
    def test_n_opcode_done(self):
        s = BindingState(is_64=True)
        s.done = False
        n_opcode_done(s, None, None, None)
        self.assertTrue(s.done)

        s = BindingState(is_64=True)
        s.done = True
        n_opcode_done(s, None, None, None)
        self.assertTrue(s.done)

    def test_n_opcode_set_dylib_ordinal_imm(self):
        s = BindingState(is_64=True)

        const = 0x123456789
        n_opcode_set_dylib_ordinal_imm(s, None, const, None)
        self.assertEqual(s.lib_ord, const)

        const = -10000
        n_opcode_set_dylib_ordinal_imm(s, None, const, None)
        self.assertEqual(s.lib_ord, const)

        const = 0
        n_opcode_set_dylib_ordinal_imm(s, None, const, None)
        self.assertEqual(s.lib_ord, const)

        const = 0x123456789123456789123456789
        n_opcode_set_dylib_ordinal_imm(s, None, const, None)
        self.assertEqual(s.lib_ord, const)

    def n_opcode_set_dylib_ordinal_uleb_helper(self, blob, expected):
        s = BindingState(is_64=True)

        s.index = 0
        n_opcode_set_dylib_ordinal_uleb(s, None, None, blob)
        self.assertEqual(s.lib_ord, expected)

    def test_n_opcode_set_dylib_ordinal_uleb(self):
        self.n_opcode_set_dylib_ordinal_uleb_helper(b"\xE5\x8E\x26", 624485)
        self.n_opcode_set_dylib_ordinal_uleb_helper(b"\x00\x00", 0)
        self.n_opcode_set_dylib_ordinal_uleb_helper(b"\x11\x00", 17)

    def test_n_opcode_set_dylib_special_imm(self):
        s = BindingState(is_64=True)

        n_opcode_set_dylib_special_imm(s, None, 0, None)
        self.assertEqual(s.lib_ord, 0)

        n_opcode_set_dylib_special_imm(s, None, 100, None)
        self.assertEqual(s.lib_ord, -12)

        n_opcode_set_dylib_special_imm(s, None, 156, None)
        self.assertEqual(s.lib_ord, -4)

        n_opcode_set_dylib_special_imm(s, None, 1, None)
        self.assertEqual(s.lib_ord, -15)

        n_opcode_set_dylib_special_imm(s, None, 88, None)
        self.assertEqual(s.lib_ord, -8)

        n_opcode_set_dylib_special_imm(s, None, 255, None)
        self.assertEqual(s.lib_ord, -1)

    def test_n_opcode_set_symbol_trailing_flags_imm(self):
        self.n_opcode_set_symbol_trailing_flags_imm_helper(b"THISISATESTSYMBOL", 100)
        self.n_opcode_set_symbol_trailing_flags_imm_helper(b"", -100)
        self.n_opcode_set_symbol_trailing_flags_imm_helper(b"ASDF", 300)

    def n_opcode_set_symbol_trailing_flags_imm_helper(self, teststr, immediate):
        s = BindingState(is_64=True)

        s.index = 0
        blob = teststr + b"\x00"

        n_opcode_set_trailing_flags_imm(s, None, immediate, blob)
        self.assertEqual(s.sym_name, teststr.decode("ascii"))
        # plus one because there is the 0 byte at the end
        self.assertEqual(s.index, len(teststr) + 1)
        self.assertEqual(s.sym_flags, immediate)

    def test_n_opcode_set_type_imm(self):
        s = BindingState(is_64=True)
        immediate = 1000
        n_opcode_set_type_imm(s, None, immediate, None)
        self.assertEqual(s.binding_type, immediate)

        immediate = 0
        n_opcode_set_type_imm(s, None, immediate, None)
        self.assertEqual(s.binding_type, immediate)

        immediate = -250
        n_opcode_set_type_imm(s, None, immediate, None)
        self.assertEqual(s.binding_type, immediate)

    def n_opcode_set_addend_sleb_helper(self, blob, expected):
        s = BindingState(is_64=True)
        s.index = 0
        n_opcode_set_addend_sleb(s, None, None, blob)
        self.assertEqual(s.addend, expected)

    def test_n_opcode_set_addend_sleb(self):
        self.n_opcode_set_addend_sleb_helper(b"\x00\x00\x00", 0)
        self.n_opcode_set_addend_sleb_helper(b"\x15\x15\x15", 21)
        self.n_opcode_set_addend_sleb_helper(b"\xFF\x1F\xEE", 4095)

    def test_n_opcode_set_segment_and_offset_uleb(self):
        BindingState(is_64=True)
        self.skipTest("TODO: The function needs a binary with segments to test")

    def test_n_opcode_add_addr_uleb(self):
        self.skipTest("TODO")

    def test_n_opcode_do_bind(self):
        self.skipTest("TODO")

    def test_n_opcode_do_bind_add_addr_uleb(self):
        self.skipTest("TODO")

    def test_n_opcode_do_bind_add_addr_imm_scaled(self):
        self.skipTest("TODO")

    def test_n_opcode_do_bind_uleb_times_skipping_uleb(self):
        self.skipTest("TODO")

    def test_bind_real_32(self):
        """
        Executes binding against a real binary - not optimal since it does not cover all possible opcodes but it is
        a start
        """
        # logging.basicConfig(filename="./test_bindinghelper_do_normal_bind_real_32.log", level=logging.DEBUG)

        machofile = os.path.join(TEST_BASE, "tests", "armhf", "FileProtection-05.armv7.macho")
        ld = cle.Loader(machofile, auto_load_libs=False)
        macho: MachO = ld.main_object
        macho.do_binding()

        expected = {
            "_OBJC_CLASS_$_UIResponder": [0xC970],
            "_OBJC_CLASS_$_UIScreen": [0xC954],
            "_OBJC_CLASS_$_UIViewController": [0xC998],
            "_OBJC_CLASS_$_UIWindow": [0xC950],
            "_OBJC_METACLASS_$_UIResponder": [0xC984],
            "_OBJC_METACLASS_$_UIViewController": [0xC9AC],
            "_OBJC_METACLASS_$_NSObject": [0xC980, 0xC9A8],
            "__objc_empty_cache": [0xC974, 0xC988, 0xC99C, 0xC9B0, 0xC9C4, 0xC9D8],
            "__objc_empty_vtable": [0xC9C8, 0xC9DC],
            "_class_getName": [0xC0EC],
            "_objc_allocateClassPair": [0xC0F4],
            "_objc_autoreleasePoolPush": [0xC048, 0xC0F8],
            "_objc_copyClassNamesForImage": [0xC0FC],
            "_objc_getClass": [0xC100, 0xC050],
            "_objc_getMetaClass": [0xC104, 0xC054],
            "_objc_getProtocol": [0xC108, 0xC058],
            "_objc_getRequiredClass": [0xC10C, 0xC05C],
            "_objc_lookUpClass": [0xC110, 0xC064],
            "_objc_readClassPair": [0xC114],
            "_objc_retain": [0xC118],
            "_object_getIndexedIvars": [0xC11C],
            "_protocol_getName": [0xC120],
            "__DefaultRuneLocale": [0xC0E4],
            "___stack_chk_guard": [0xC0E8],
            "dyld_stub_binder": [0xC0DC],
            "___CFConstantStringClassReference": [0xC124, 0xC134, 0xC144],
            "_kCFCoreFoundationVersionNumber": [0xC0F0],
            "_UIApplicationMain": [0xC000],
            "_NSSearchPathForDirectoriesInDomains": [0xC004],
            "_NSStringFromClass": [0xC008],
            "_class_addMethod": [0xC00C],
            "_class_addProperty": [0xC010],
            "_class_addProtocol": [0xC014],
            "_class_getInstanceMethod": [0xC018],
            "_class_getInstanceSize": [0xC01C],
            "_class_getInstanceVariable": [0xC020],
            "_class_getIvarLayout": [0xC024],
            "_class_getSuperclass": [0xC028],
            "_class_isMetaClass": [0xC02C],
            "_class_replaceMethod": [0xC030],
            "_class_respondsToSelector": [0xC034],
            "_ivar_getName": [0xC038],
            "_ivar_getOffset": [0xC03C],
            "_method_setImplementation": [0xC040],
            "_objc_autoreleasePoolPop": [0xC044],
            "_objc_constructInstance": [0xC04C],
            "_objc_initializeClassPair": [0xC060],
            "_objc_msgSend": [0xC068],
            "_objc_msgSendSuper2": [0xC06C],
            "_objc_msgSend_stret": [0xC070],
            "_objc_registerClassPair": [0xC074],
            "_objc_setProperty_nonatomic": [0xC078],
            "_object_getClass": [0xC07C],
            "_object_getIvar": [0xC080],
            "_object_setIvar": [0xC084],
            "_property_copyAttributeList": [0xC088],
            "_protocol_getMethodDescription": [0xC08C],
            "_sel_getUid": [0xC090],
            "__Block_copy": [0xC094],
            "___stack_chk_fail": [0xC098],
            "__dyld_register_func_for_add_image": [0xC09C],
            "_asprintf": [0xC0A0],
            "_bzero": [0xC0A4],
            "_calloc": [0xC0A8],
            "_free": [0xC0AC],
            "_hash_create": [0xC0B0],
            "_hash_search": [0xC0B4],
            "_malloc": [0xC0B8],
            "_memcmp": [0xC0BC],
            "_memcpy": [0xC0C0],
            "_pthread_mutex_lock": [0xC0C4],
            "_pthread_mutex_unlock": [0xC0C8],
            "_strcmp": [0xC0CC],
            "_strlen": [0xC0D0],
            "_strncmp": [0xC0D4],
            "_CFStringGetCStringPtr": [0xC0D8],
        }

        for name, xrefs in expected.items():
            found = False
            for sym in macho.get_symbol(name):
                found = True
                b = sorted(sym.bind_xrefs)
                a = sorted(xrefs)
                self.assertEqual(
                    a,
                    b,
                    f"Error: Differences for symbol {name}: {a} != {b}: ",
                )

            if not found:
                self.fail(f"Symbol not found: {name}")

    def test_bind_real_64(self):
        """
        Executes binding against a real binary - not optimal since it does not cover all possible opcodes but it is
        a start
        """
        machofile = os.path.join(TEST_BASE, "tests", "armhf", "FileProtection-05.arm64.macho")
        ld = cle.Loader(machofile, auto_load_libs=False)
        assert isinstance(ld.main_object, MachO)
        macho: MachO = ld.main_object
        macho.do_binding()
        expected = {
            "_OBJC_CLASS_$_UIResponder": [0x100009128],
            "_OBJC_CLASS_$_UIScreen": [0x1000090F8],
            "_OBJC_CLASS_$_UIViewController": [0x100009178],
            "_OBJC_CLASS_$_UIWindow": [0x1000090F0],
            "_OBJC_METACLASS_$_UIResponder": [0x100009150],
            "_OBJC_METACLASS_$_UIViewController": [0x1000091A0],
            "_OBJC_METACLASS_$_NSObject": [0x100009148, 0x100009198],
            "__objc_empty_cache": [
                0x100009130,
                0x100009158,
                0x100009180,
                0x1000091A8,
                0x1000091D0,
                0x1000091F8,
            ],
            "__objc_empty_vtable": [0x1000091D8, 0x100009200],
            "_class_getName": [0x100008010],
            "_objc_allocateClassPair": [0x100008020],
            "_objc_copyClassNamesForImage": [0x100008028],
            "_objc_getClass": [0x100008030, 0x1000080F8],
            "_objc_getMetaClass": [0x100008038, 0x100008100],
            "_objc_getProtocol": [0x100008040, 0x100008108],
            "_objc_getRequiredClass": [0x100008048, 0x100008110],
            "_objc_lookUpClass": [0x100008050, 0x100008120],
            "_objc_readClassPair": [0x100008058],
            "_object_getIndexedIvars": [0x100008060],
            "_protocol_getName": [0x100008068],
            "__DefaultRuneLocale": [0x100008000],
            "___stack_chk_guard": [0x100008008],
            "dyld_stub_binder": [0x100008070],
            "___CFConstantStringClassReference": [
                0x1000081F8,
                0x100008218,
                0x100008238,
            ],
            "_kCFCoreFoundationVersionNumber": [0x100008018],
            "_UIApplicationMain": [0x100008080],
            "_NSSearchPathForDirectoriesInDomains": [0x100008088],
            "_NSStringFromClass": [0x100008090],
            "_class_addMethod": [0x100008098],
            "_class_addProperty": [0x1000080A0],
            "_class_addProtocol": [0x1000080A8],
            "_class_getInstanceMethod": [0x1000080B0],
            "_class_getInstanceVariable": [0x1000080B8],
            "_class_getSuperclass": [0x1000080C0],
            "_class_isMetaClass": [0x1000080C8],
            "_class_replaceMethod": [0x1000080D0],
            "_method_setImplementation": [0x1000080D8],
            "_objc_autoreleasePoolPop": [0x1000080E0],
            "_objc_autoreleasePoolPush": [0x1000080E8],
            "_objc_constructInstance": [0x1000080F0],
            "_objc_initializeClassPair": [0x100008118],
            "_objc_msgSend": [0x100008128],
            "_objc_msgSendSuper2": [0x100008130],
            "_objc_registerClassPair": [0x100008138],
            "_objc_setProperty_nonatomic": [0x100008140],
            "_object_getClass": [0x100008148],
            "_object_getIvar": [0x100008150],
            "_property_copyAttributeList": [0x100008158],
            "_protocol_getMethodDescription": [0x100008160],
            "_sel_getUid": [0x100008168],
            "___stack_chk_fail": [0x100008170],
            "__dyld_register_func_for_add_image": [0x100008178],
            "_asprintf": [0x100008180],
            "_bzero": [0x100008188],
            "_calloc": [0x100008190],
            "_free": [0x100008198],
            "_hash_create": [0x1000081A0],
            "_hash_search": [0x1000081A8],
            "_malloc": [0x1000081B0],
            "_memcmp": [0x1000081B8],
            "_memcpy": [0x1000081C0],
            "_pthread_mutex_lock": [0x1000081C8],
            "_pthread_mutex_unlock": [0x1000081D0],
            "_strcmp": [0x1000081D8],
            "_strlen": [0x1000081E0],
            "_strncmp": [0x1000081E8],
            "_CFStringGetCStringPtr": [0x1000081F0],
        }

        executed = False

        for name, xrefs in expected.items():
            found = False
            for sym in macho.get_symbol(name):
                found = True
                b = sorted(sym.bind_xrefs)
                a = sorted(xrefs)
                self.assertEqual(
                    a,
                    b,
                    f"Error: Differences for symbol {name}: {a} != {b}: ",
                )

            if not found:
                self.fail(f"Symbol not found: {name}")

            executed = True

        if not executed:
            self.fail("Not executed")


if __name__ == "__main__":
    unittest.main()
