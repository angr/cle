#!/usr/bin/env python
# Contributed September 2019 by Fraunhofer SIT (https://www.sit.fraunhofer.de/en/).
import unittest
import os

import cle

from cle.backends.macho.binding import BindingState,read_sleb,read_uleb

from cle.backends.macho.binding import n_opcode_done,n_opcode_set_dylib_ordinal_imm,n_opcode_set_dylib_ordinal_uleb
from cle.backends.macho.binding import n_opcode_set_dylib_special_imm,n_opcode_set_trailing_flags_imm,n_opcode_set_type_imm
from cle.backends.macho.binding import n_opcode_set_addend_sleb

from cle import CLEInvalidBinaryError

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))


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
        self.skipTest("TODO test_add_address_ov_32: add_address_ov does not consider the 64 bit flag and does not change the "
                      "size of uintptr_t to 2**32 so calculation will fail")

        self.uut_32.add_address_ov(10000, 10000)
        self.assertEqual(self.uut_32.address, 20000)

        self.uut_32.add_address_ov(699999999, 10000000)
        self.assertEqual(self.uut_32.address, 709999999)

        self.uut_32.add_address_ov(4294967295, 10000)
        self.assertEqual(self.uut_32.address, 9999)

        self.uut_32.add_address_ov(3294967295, 1000100000)
        self.assertEqual(self.uut_32.address, 99999)

        #TODO test_add_address_ov_32: we do probably do not expect negative numbers as second argument, but then the address will be negative... and it does not wrap around. Test is commented out.
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


        #TODO test_add_address_ov_64: we do probably do not expect negative numbers as second argument, but then the address will be negative... and it does not wrap around. Test is commented out.
        #self.uut_64.add_address_ov(123456, -10000000000)
        #self.assertEqual(self.uut_64.address, 18446744063709551616)

        self.uut_64.add_address_ov(1000, -1000)
        self.assertEqual(self.uut_64.address, 0)



    def test_check_address_bounds(self):
        """Ensure that exception gets thrown under the right circumstances"""
        self.uut_64 = BindingState(True)

        #TODO test_check_address_bounds: Why does this raise an exception?
        # address and seg_end address are not 0 when entering the function
        #self.uut_64.address = 0
        #self.uut_64.seg_end_address = 0
        #self.uut_64.check_address_bounds()

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
        buffer = b'\xE5\x8E\x26'
        expected = (624485,3)
        result = read_uleb(buffer,0)
        self.assertEqual(expected,result)

    def test_read_sleb(self):
        # Test vector from wikipedia https://en.wikipedia.org/wiki/LEB128
        buffer = b'\xE5\x8E\x26'
        expected = (624485,3)
        result = read_sleb(buffer,0)
        self.assertEqual(expected,result)

        buffer = b'\x9b\xf1\x59'
        result= read_sleb(buffer,0)
        expected = (-624485,3)
        self.assertEqual(result,expected)


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
        self.assertEqual(s.sym_name, teststr.decode('ascii'))
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
        # pylint: disable=unused-variable
        s = BindingState(is_64=True)
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
        #logging.basicConfig(filename="./test_bindinghelper_do_normal_bind_real_32.log", level=logging.DEBUG)

        machofile = os.path.join(TEST_BASE, 'tests', 'armhf', 'FileProtection-05.armv7.macho')
        ld = cle.Loader(machofile, auto_load_libs=False)
        macho = ld.main_object
        macho.do_binding()

        expected = {
            "_OBJC_CLASS_$_UIResponder": [0xc970],
            "_OBJC_CLASS_$_UIScreen": [0xc954],
            "_OBJC_CLASS_$_UIViewController": [0xc998],
            "_OBJC_CLASS_$_UIWindow": [0xc950],
            "_OBJC_METACLASS_$_UIResponder": [0xc984],
            "_OBJC_METACLASS_$_UIViewController": [0xc9ac],
            "_OBJC_METACLASS_$_NSObject": [0xc980, 0xc9a8],
            "__objc_empty_cache": [0xc974, 0xc988, 0xc99c, 0xc9b0, 0xc9c4, 0xc9d8],
            "__objc_empty_vtable": [0xc9c8, 0xc9dc],
            "_class_getName": [0xc0ec],
            "_objc_allocateClassPair": [0xc0f4],
            "_objc_autoreleasePoolPush": [0xc048, 0xc0f8],
            "_objc_copyClassNamesForImage": [0xc0fc],
            "_objc_getClass": [0xc100, 0xc050],
            "_objc_getMetaClass": [0xc104, 0xc054],
            "_objc_getProtocol": [0xc108, 0xc058],
            "_objc_getRequiredClass": [0xc10c, 0xc05c],
            "_objc_lookUpClass": [0xc110, 0xc064],
            "_objc_readClassPair": [0xc114],
            "_objc_retain": [0xc118],
            "_object_getIndexedIvars": [0xc11c],
            "_protocol_getName": [0xc120],
            "__DefaultRuneLocale": [0xc0e4],
            "___stack_chk_guard": [0xc0e8],
            "dyld_stub_binder": [0xc0dc],
            "___CFConstantStringClassReference": [0xc124, 0xc134, 0xc144],
            "_kCFCoreFoundationVersionNumber": [0xc0f0],
            "_UIApplicationMain": [0xc000],
            "_NSSearchPathForDirectoriesInDomains": [0xc004],
            "_NSStringFromClass": [0xc008],
            "_class_addMethod": [0xc00c],
            "_class_addProperty": [0xc010],
            "_class_addProtocol": [0xc014],
            "_class_getInstanceMethod": [0xc018],
            "_class_getInstanceSize": [0xc01c],
            "_class_getInstanceVariable": [0xc020],
            "_class_getIvarLayout": [0xc024],
            "_class_getSuperclass": [0xc028],
            "_class_isMetaClass": [0xc02c],
            "_class_replaceMethod": [0xc030],
            "_class_respondsToSelector": [0xc034],
            "_ivar_getName": [0xc038],
            "_ivar_getOffset": [0xc03c],
            "_method_setImplementation": [0xc040],
            "_objc_autoreleasePoolPop": [0xc044],
            "_objc_constructInstance": [0xc04c],
            "_objc_initializeClassPair": [0xc060],
            "_objc_msgSend": [0xc068],
            "_objc_msgSendSuper2": [0xc06c],
            "_objc_msgSend_stret": [0xc070],
            "_objc_registerClassPair": [0xc074],
            "_objc_setProperty_nonatomic": [0xc078],
            "_object_getClass": [0xc07c],
            "_object_getIvar": [0xc080],
            "_object_setIvar": [0xc084],
            "_property_copyAttributeList": [0xc088],
            "_protocol_getMethodDescription": [0xc08c],
            "_sel_getUid": [0xc090],
            "__Block_copy": [0xc094],
            "___stack_chk_fail": [0xc098],
            "__dyld_register_func_for_add_image": [0xc09c],
            "_asprintf": [0xc0a0],
            "_bzero": [0xc0a4],
            "_calloc": [0xc0a8],
            "_free": [0xc0ac],
            "_hash_create": [0xc0b0],
            "_hash_search": [0xc0b4],
            "_malloc": [0xc0b8],
            "_memcmp": [0xc0bc],
            "_memcpy": [0xc0c0],
            "_pthread_mutex_lock": [0xc0c4],
            "_pthread_mutex_unlock": [0xc0c8],
            "_strcmp": [0xc0cc],
            "_strlen": [0xc0d0],
            "_strncmp": [0xc0d4],
            "_CFStringGetCStringPtr": [0xc0d8]
        }

        for (name, xrefs) in expected.items():
            found = False
            for sym in macho.get_symbol(name):
                found = True
                b = sorted(sym.bind_xrefs)
                a = sorted(xrefs)
                self.assertEqual(a, b, "Error: Differences for symbol {0}: {1} != {2}: ".format(name, a, b))

            if not found:
                self.fail("Symbol not found: {0}".format(name))

    def test_bind_real_64(self):
        """
        Executes binding against a real binary - not optimal since it does not cover all possible opcodes but it is
        a start
        """
        machofile = os.path.join(TEST_BASE, 'tests', 'armhf', 'FileProtection-05.arm64.macho')
        ld = cle.Loader(machofile, auto_load_libs=False)
        macho = ld.main_object
        macho.do_binding()
        expected = {
            "_OBJC_CLASS_$_UIResponder": [0x100009128],
            "_OBJC_CLASS_$_UIScreen": [0x1000090f8],
            "_OBJC_CLASS_$_UIViewController": [0x100009178],
            "_OBJC_CLASS_$_UIWindow": [0x1000090f0],
            "_OBJC_METACLASS_$_UIResponder": [0x100009150],
            "_OBJC_METACLASS_$_UIViewController": [0x1000091a0],
            "_OBJC_METACLASS_$_NSObject": [0x100009148, 0x100009198],
            "__objc_empty_cache": [0x100009130, 0x100009158, 0x100009180, 0x1000091a8, 0x1000091d0, 0x1000091f8],
            "__objc_empty_vtable": [0x1000091d8, 0x100009200],
            "_class_getName": [0x100008010],
            "_objc_allocateClassPair": [0x100008020],
            "_objc_copyClassNamesForImage": [0x100008028],
            "_objc_getClass": [0x100008030, 0x1000080f8],
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
            "___CFConstantStringClassReference": [0x1000081f8, 0x100008218, 0x100008238],
            "_kCFCoreFoundationVersionNumber": [0x100008018],
            "_UIApplicationMain": [0x100008080],
            "_NSSearchPathForDirectoriesInDomains": [0x100008088],
            "_NSStringFromClass": [0x100008090],
            "_class_addMethod": [0x100008098],
            "_class_addProperty": [0x1000080a0],
            "_class_addProtocol": [0x1000080a8],
            "_class_getInstanceMethod": [0x1000080b0],
            "_class_getInstanceVariable": [0x1000080b8],
            "_class_getSuperclass": [0x1000080c0],
            "_class_isMetaClass": [0x1000080c8],
            "_class_replaceMethod": [0x1000080d0],
            "_method_setImplementation": [0x1000080d8],
            "_objc_autoreleasePoolPop": [0x1000080e0],
            "_objc_autoreleasePoolPush": [0x1000080e8],
            "_objc_constructInstance": [0x1000080f0],
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
            "_hash_create": [0x1000081a0],
            "_hash_search": [0x1000081a8],
            "_malloc": [0x1000081b0],
            "_memcmp": [0x1000081b8],
            "_memcpy": [0x1000081c0],
            "_pthread_mutex_lock": [0x1000081c8],
            "_pthread_mutex_unlock": [0x1000081d0],
            "_strcmp": [0x1000081d8],
            "_strlen": [0x1000081e0],
            "_strncmp": [0x1000081e8],
            "_CFStringGetCStringPtr": [0x1000081f0]
        }

        executed = False

        for (name, xrefs) in expected.items():
            found = False
            for sym in macho.get_symbol(name):
                found = True
                b = sorted(sym.bind_xrefs)
                a = sorted(xrefs)
                self.assertEqual(a, b, "Error: Differences for symbol {0}: {1} != {2}: ".format(name, a, b))

            if not found:
                self.fail("Symbol not found: {0}".format(name))

            executed = True

        if not executed:
            self.fail("Not executed")


if __name__ == '__main__':
    # TODO run the testclasses without having to run each test in case the CI needs this
    raise NotImplementedError()
