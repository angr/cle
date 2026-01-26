#!/usr/bin/env python
from __future__ import annotations

import os
import shutil
import tempfile
import unittest

import pefile

import cle
from cle.backends.pe.symbolserver import PDBInfo

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
                ".text",
                ".rdata",
                ".data",
                ".idata",
                ".tls",
                ".gfids",
                ".00cfg",
                ".rsrc",
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

    def test_long_section_names(self):
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "simple_crackme_x64.exe")
        ld = cle.Loader(exe, auto_load_libs=False)
        section_names = [section.name for section in ld.main_object.sections]

        # Assert no string table references remain
        assert not any(name.startswith("/") for name in section_names)

        debug_section_names = [
            ".debug_aranges",
            ".debug_info",
            ".debug_abbrev",
            ".debug_line",
            ".debug_frame",
            ".debug_str",
            ".debug_loc",
            ".debug_ranges",
        ]
        assert section_names[-len(debug_section_names) :] == debug_section_names

    def test_coff_symbol_loaded(self):
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "simple_crackme_x64.exe")
        ld = cle.Loader(exe, auto_load_libs=False)
        assert ld.find_symbol("main")

    def test_debug_symbol_paths_flat_layout(self):
        """Test loading PDB from debug_symbol_paths with flat layout."""
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.exe")
        pdb = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.pdb")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy PDB to a separate directory (flat layout)
            pdb_dest = os.path.join(tmpdir, "fauxware.pdb")
            shutil.copy(pdb, pdb_dest)

            # Load with debug_symbol_paths pointing to the temp directory
            ld = cle.Loader(exe, auto_load_libs=False, load_debug_info=True, main_opts={"debug_symbol_paths": [tmpdir]})
            assert ld.find_symbol("authenticate")

    def test_debug_symbol_paths_symbol_store_layout(self):
        """Test loading PDB from debug_symbol_paths with symbol store layout."""
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.exe")
        pdb = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.pdb")

        with tempfile.TemporaryDirectory() as tmpdir:
            # First, load the PE to get the PDB info
            pe = pefile.PE(exe, fast_load=True)
            pe.parse_data_directories()
            pdb_info = PDBInfo.from_pe(pe)
            pe.close()

            # Create symbol store layout: tmpdir/pdbname/signature/pdbname
            if pdb_info:
                store_dir = os.path.join(tmpdir, pdb_info.pdb_name, pdb_info.signature_id)
                os.makedirs(store_dir)
                pdb_dest = os.path.join(store_dir, pdb_info.pdb_name)
                shutil.copy(pdb, pdb_dest)

                # Load with debug_symbol_paths pointing to the temp directory
                ld = cle.Loader(
                    exe, auto_load_libs=False, load_debug_info=True, main_opts={"debug_symbol_paths": [tmpdir]}
                )
                assert ld.find_symbol("authenticate")

    def test_debug_symbol_paths_multiple_paths(self):
        """Test loading PDB with multiple debug_symbol_paths."""
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.exe")
        pdb = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.pdb")

        with tempfile.TemporaryDirectory() as tmpdir1:
            with tempfile.TemporaryDirectory() as tmpdir2:
                # Put PDB in second directory
                pdb_dest = os.path.join(tmpdir2, "fauxware.pdb")
                shutil.copy(pdb, pdb_dest)

                # Load with both paths, PDB should be found in second path
                ld = cle.Loader(
                    exe,
                    auto_load_libs=False,
                    load_debug_info=True,
                    main_opts={"debug_symbol_paths": [tmpdir1, tmpdir2]},
                )
                assert ld.find_symbol("authenticate")

    def test_debug_symbol_paths_nonexistent_path(self):
        """Test that nonexistent debug_symbol_paths are handled gracefully."""
        exe = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.exe")
        pdb = os.path.join(TEST_BASE, "tests", "x86_64", "windows", "fauxware.pdb")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Copy PDB to valid directory
            pdb_dest = os.path.join(tmpdir, "fauxware.pdb")
            shutil.copy(pdb, pdb_dest)

            # Include a nonexistent path before the valid one
            nonexistent = "/nonexistent/path/that/does/not/exist"
            ld = cle.Loader(
                exe,
                auto_load_libs=False,
                load_debug_info=True,
                main_opts={"debug_symbol_paths": [nonexistent, tmpdir]},
            )
            assert ld.find_symbol("authenticate")


if __name__ == "__main__":
    unittest.main()
