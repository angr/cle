#!/usr/bin/env python

import logging
import nose
import os

import cle

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         os.path.join('..', '..', 'binaries'))

def test_exe():
    exe = os.path.join(TEST_BASE, 'tests', 'x86', 'windows', 'TLS.exe')
    ld = cle.Loader(exe, auto_load_libs=False)
    nose.tools.assert_true(isinstance(ld.main_bin,cle.PE))
    nose.tools.assert_equals(ld.main_bin.os, 'windows')
    nose.tools.assert_equals(sorted([sec.name for sec in ld.main_bin.sections]),
                             sorted(['.textbss',
                                     '.text\x00\x00\x00',
                                     '.rdata\x00\x00',
                                     '.data\x00\x00\x00',
                                     '.idata\x00\x00',
                                     '.tls\x00\x00\x00\x00',
                                     '.gfids\x00\x00',
                                     '.00cfg\x00\x00',
                                     '.rsrc\x00\x00\x00']))
    nose.tools.assert_equals(ld.main_bin.segments.raw_list, [])
    nose.tools.assert_equals(sorted(ld.main_bin.deps),
                             sorted(['KERNEL32.dll',
                                     'VCRUNTIME140D.dll',
                                     'ucrtbased.dll']))
    nose.tools.assert_equals(sorted(ld.main_bin.imports),
                             sorted(['_configure_narrow_argv',
                                     'GetLastError',
                                     'HeapFree',
                                     'IsProcessorFeaturePresent',
                                     '__vcrt_GetModuleFileNameW',
                                     '_configthreadlocale',
                                     '__setusermatherr',
                                     'memset',
                                     'terminate',
                                     '_register_onexit_function',
                                     'WaitForSingleObject',
                                     '_set_fmode',
                                     'FreeLibrary',
                                     'QueryPerformanceCounter',
                                     '_controlfp_s',
                                     'IsDebuggerPresent',
                                     'HeapAlloc',
                                     '_initialize_onexit_table',
                                     'wcscpy_s',
                                     '__std_type_info_destroy_list',
                                     '_set_app_type',
                                     '_cexit',
                                     '_seh_filter_exe',
                                     '_c_exit',
                                     'GetCurrentProcess',
                                     '_set_new_mode',
                                     '__vcrt_LoadLibraryExW',
                                     '__stdio_common_vsprintf_s',
                                     'GetCurrentProcessId',
                                     '_execute_onexit_table',
                                     'WideCharToMultiByte',
                                     'UnhandledExceptionFilter',
                                     'MultiByteToWideChar',
                                     'GetStartupInfoW',
                                     'exit',
                                     'GetProcAddress',
                                     'InitializeSListHead',
                                     '_crt_at_quick_exit',
                                     'GetProcessHeap',
                                     '_CrtDbgReportW',
                                     'RaiseException',
                                     '__telemetry_main_invoke_trigger',
                                     'CreateThread',
                                     '_exit',
                                     '__p__commode',
                                     '_get_initial_narrow_environment',
                                     '__p___argc',
                                     'SetUnhandledExceptionFilter',
                                     '_except_handler4_common',
                                     '_register_thread_local_exe_atexit_callback',
                                     'GetSystemTimeAsFileTime',
                                     '_initialize_narrow_environment',
                                     '__vcrt_GetModuleHandleW',
                                     '__p___argv',
                                     'GetModuleHandleW',
                                     'TerminateProcess',
                                     '_initterm_e',
                                     '_wmakepath_s',
                                     '_seh_filter_dll',
                                     '_CrtDbgReport',
                                     'VirtualQuery',
                                     '__telemetry_main_return_trigger',
                                     '_wsplitpath_s',
                                     '_initterm',
                                     'GetCurrentThreadId',
                                     '_crt_atexit']))
    nose.tools.assert_is_none(ld.main_bin.provides)

def test_dll():
    pass

def test_tls():
    exe = os.path.join(TEST_BASE, 'tests', 'x86', 'windows', 'TLS.exe')
    ld = cle.Loader(exe, auto_load_libs=False)

    nose.tools.assert_true(ld.main_bin.tls_used)
    nose.tools.assert_equals(ld.main_bin.tls_data_start, 0x41b000)
    nose.tools.assert_equals(ld.main_bin.tls_data_size, 520)
    nose.tools.assert_equals(ld.main_bin.tls_index_address, 0x41913C)
    nose.tools.assert_equals(ld.main_bin.tls_callbacks, [0x411302])
    nose.tools.assert_equals(ld.main_bin.tls_size_of_zero_fill, 0)

    tls = ld.tls_object
    nose.tools.assert_is_not_none(tls)
    nose.tools.assert_equals(len(tls.modules), 1)
    nose.tools.assert_equals(tls.get_tls_data_addr(0), 0x1000004)
    nose.tools.assert_raises(IndexError, tls.get_tls_data_addr, 1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    test_exe()
    test_dll()
    test_tls()
