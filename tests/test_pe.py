#!/usr/bin/env python
from __future__ import annotations

import os
import unittest

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))


# pylint: disable=no-self-use
class TestPEBackend(unittest.TestCase):
    """
    Test PE Backend
    """

    def test_exe(self):
        exe = os.path.join(TEST_BASE, "tests", "x86", "windows", "TLS.exe")
        ld = cle.Loader(exe, auto_load_libs=False)
        assert isinstance(ld.main_object, cle.PE)
        assert ld.main_object.os == "windows"
        assert sorted([sec.name for sec in ld.main_object.sections]) == sorted(
            [
                ".textbss",
                ".text\x00\x00\x00",
                ".rdata\x00\x00",
                ".data\x00\x00\x00",
                ".idata\x00\x00",
                ".tls\x00\x00\x00\x00",
                ".gfids\x00\x00",
                ".00cfg\x00\x00",
                ".rsrc\x00\x00\x00",
            ]
        )
        assert ld.main_object.segments is ld.main_object.sections
        assert sorted(ld.main_object.deps) == sorted(["kernel32.dll", "vcruntime140d.dll", "ucrtbased.dll"])
        assert sorted(ld.main_object.imports) == sorted(
            [
                "_configure_narrow_argv",
                "GetLastError",
                "HeapFree",
                "IsProcessorFeaturePresent",
                "__vcrt_GetModuleFileNameW",
                "_configthreadlocale",
                "__setusermatherr",
                "memset",
                "terminate",
                "_register_onexit_function",
                "WaitForSingleObject",
                "_set_fmode",
                "FreeLibrary",
                "QueryPerformanceCounter",
                "_controlfp_s",
                "IsDebuggerPresent",
                "HeapAlloc",
                "_initialize_onexit_table",
                "wcscpy_s",
                "__std_type_info_destroy_list",
                "_set_app_type",
                "_cexit",
                "_seh_filter_exe",
                "_c_exit",
                "GetCurrentProcess",
                "_set_new_mode",
                "__vcrt_LoadLibraryExW",
                "__stdio_common_vsprintf_s",
                "GetCurrentProcessId",
                "_execute_onexit_table",
                "WideCharToMultiByte",
                "UnhandledExceptionFilter",
                "MultiByteToWideChar",
                "GetStartupInfoW",
                "exit",
                "GetProcAddress",
                "InitializeSListHead",
                "_crt_at_quick_exit",
                "GetProcessHeap",
                "_CrtDbgReportW",
                "RaiseException",
                "__telemetry_main_invoke_trigger",
                "CreateThread",
                "_exit",
                "__p__commode",
                "_get_initial_narrow_environment",
                "__p___argc",
                "SetUnhandledExceptionFilter",
                "_except_handler4_common",
                "_register_thread_local_exe_atexit_callback",
                "GetSystemTimeAsFileTime",
                "_initialize_narrow_environment",
                "__vcrt_GetModuleHandleW",
                "__p___argv",
                "GetModuleHandleW",
                "TerminateProcess",
                "_initterm_e",
                "_wmakepath_s",
                "_seh_filter_dll",
                "_CrtDbgReport",
                "VirtualQuery",
                "__telemetry_main_return_trigger",
                "_wsplitpath_s",
                "_initterm",
                "GetCurrentThreadId",
                "_crt_atexit",
            ]
        )
        assert ld.main_object.provides is None

    def test_tls(self):
        exe = os.path.join(TEST_BASE, "tests", "x86", "windows", "TLS.exe")
        ld = cle.Loader(exe, auto_load_libs=False)
        tls = ld.tls.new_thread()

        assert ld.main_object.tls_used
        assert ld.main_object.tls_data_start == 0x1B000
        assert ld.main_object.tls_data_size == 520
        assert ld.main_object.tls_index_address == 0x41913C
        assert ld.main_object.tls_callbacks == [0x411302]
        assert ld.main_object.tls_block_size == ld.main_object.tls_data_size

        assert tls is not None
        assert len(ld.tls.modules) == 1
        assert tls.get_tls_data_addr(0) == tls.memory.unpack_word(0)

    @unittest.skipUnless(cle.backends.pe.pe.PDB_SUPPORT_ENABLED, "PDB")
    def test_pdb(self):
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.exe")
        pdb = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.pdb")

        ld = cle.Loader(exe, auto_load_libs=False)
        assert not ld.find_symbol("authenticate")

        # Automatically find fauxware.pdb
        ld = cle.Loader(exe, auto_load_libs=False, load_debug_info=True)
        assert ld.find_symbol("authenticate")

        # Manually specify fauxware.pdb
        ld = cle.Loader(exe, auto_load_libs=False, main_opts={"debug_symbols": pdb})
        assert ld.find_symbol("authenticate")


if __name__ == "__main__":
    unittest.main()
