#!/usr/bin/env python
from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cle.backends.pe.symbolserver import (
    DownloadCancelledError,
    PDBInfo,
    SymbolPathEntry,
    SymbolPathParser,
    SymbolResolver,
    SymbolServerClient,
)


class TestPDBInfo(unittest.TestCase):
    """Test PDBInfo dataclass and parsing."""

    def test_signature_id_format(self):
        """Test that signature_id is correctly formatted."""
        info = PDBInfo(
            pdb_name="test.pdb",
            guid="AABBCCDD11223344AABBCCDD11223344",
            age=1,
            signature_id="AABBCCDD11223344AABBCCDD112233441",
        )
        assert info.signature_id == "AABBCCDD11223344AABBCCDD112233441"

    def test_from_pe_no_debug_directory(self):
        """Test from_pe returns None when no debug directory."""
        mock_pe = MagicMock()
        del mock_pe.DIRECTORY_ENTRY_DEBUG  # Ensure attribute doesn't exist

        result = PDBInfo.from_pe(mock_pe)
        assert result is None

    def test_from_pe_rsds_format(self):
        """Test parsing RSDS (PDB 7.0) debug info."""
        mock_pe = MagicMock()
        mock_entry = MagicMock()
        mock_entry.struct.Type = 2  # IMAGE_DEBUG_TYPE_CODEVIEW
        mock_entry.entry.name = "CV_INFO_PDB70"
        mock_entry.entry.CvSignature = b"RSDS"
        mock_entry.entry.Signature_Data1 = 0x12345678
        mock_entry.entry.Signature_Data2 = 0xABCD
        mock_entry.entry.Signature_Data3 = 0xEF01
        mock_entry.entry.Signature_Data4 = 0x1122
        mock_entry.entry.Signature_Data5 = 0x3344
        mock_entry.entry.Signature_Data6_value = 0x55667788
        mock_entry.entry.Age = 1
        mock_entry.entry.PdbFileName = b"C:\\path\\to\\test.pdb\x00"
        mock_pe.DIRECTORY_ENTRY_DEBUG = [mock_entry]

        result = PDBInfo.from_pe(mock_pe)

        assert result is not None
        assert result.pdb_name == "test.pdb"
        assert result.guid == "12345678ABCDEF011122334455667788"
        assert result.age == 1
        assert result.signature_id == "12345678ABCDEF0111223344556677881"

    def test_from_pe_nb10_format(self):
        """Test parsing NB10 (PDB 2.0) debug info."""
        mock_pe = MagicMock()
        mock_entry = MagicMock()
        mock_entry.struct.Type = 2  # IMAGE_DEBUG_TYPE_CODEVIEW
        mock_entry.entry.name = "CV_INFO_PDB20"
        mock_entry.entry.CvSignature = b"NB10"
        mock_entry.entry.TimeDateStamp = 0xDEADBEEF
        mock_entry.entry.Age = 2
        mock_entry.entry.PdbFileName = b"old.pdb\x00"
        mock_pe.DIRECTORY_ENTRY_DEBUG = [mock_entry]

        result = PDBInfo.from_pe(mock_pe)

        assert result is not None
        assert result.pdb_name == "old.pdb"
        assert result.guid == "DEADBEEF"
        assert result.age == 2
        assert result.signature_id == "DEADBEEF2"


class TestSymbolPathParser(unittest.TestCase):
    """Test SymbolPathParser functionality."""

    def test_parse_empty_path(self):
        """Test parsing empty symbol path."""
        result = SymbolPathParser.parse("")
        assert result == []

        result = SymbolPathParser.parse(None)
        assert result == []

    def test_parse_simple_local_path(self):
        """Test parsing simple local path."""
        result = SymbolPathParser.parse("/home/user/symbols")
        assert len(result) == 1
        assert result[0].entry_type == "local"
        assert result[0].local_path == "/home/user/symbols"
        assert result[0].cache_path is None
        assert result[0].server_url is None

    def test_parse_windows_local_path(self):
        """Test parsing Windows-style local path."""
        # Note: This test may behave differently on Windows vs Linux
        result = SymbolPathParser.parse("C:\\Symbols")
        # On Linux, C:\Symbols is not an absolute path, so it may not be parsed as local
        # This test verifies the behavior
        if os.name == "nt":
            assert len(result) == 1
            assert result[0].entry_type == "local"

    def test_parse_srv_with_cache_and_server(self):
        """Test parsing srv*cache*server format."""
        result = SymbolPathParser.parse("srv*~/cache*https://msdl.microsoft.com/download/symbols")
        assert len(result) == 1
        assert result[0].entry_type == "srv"
        assert "cache" in result[0].cache_path
        assert result[0].server_url == "https://msdl.microsoft.com/download/symbols"

    def test_parse_srv_with_server_only(self):
        """Test parsing srv*server format (no cache)."""
        result = SymbolPathParser.parse("srv*https://example.com/symbols")
        assert len(result) == 1
        assert result[0].entry_type == "srv"
        assert result[0].cache_path is None
        assert result[0].server_url == "https://example.com/symbols"

    def test_parse_cache_directive(self):
        """Test that cache* directive affects subsequent srv entries."""
        result = SymbolPathParser.parse("cache*/tmp/symcache;srv*https://server1;srv*https://server2")
        assert len(result) == 2
        # Both srv entries should use the cache directive
        assert result[0].cache_path == "/tmp/symcache"
        assert result[1].cache_path == "/tmp/symcache"

    def test_parse_symsrv_format(self):
        """Test parsing symsrv*dll*cache*server format."""
        result = SymbolPathParser.parse("symsrv*symsrv.dll*/tmp/cache*https://server.com")
        assert len(result) == 1
        assert result[0].entry_type == "srv"
        assert result[0].cache_path == "/tmp/cache"
        assert result[0].server_url == "https://server.com"

    def test_parse_multiple_entries(self):
        """Test parsing multiple semicolon-separated entries."""
        path = "/local/path;srv*/tmp/cache*https://server1;srv*https://server2"
        result = SymbolPathParser.parse(path)
        assert len(result) == 3
        assert result[0].entry_type == "local"
        assert result[1].entry_type == "srv"
        assert result[2].entry_type == "srv"

    def test_parse_ignores_empty_entries(self):
        """Test that empty entries are ignored."""
        result = SymbolPathParser.parse(";;/path;;")
        assert len(result) == 1
        assert result[0].local_path == "/path"

    def test_get_default_cache_dir(self):
        """Test default cache directory calculation."""
        cache_dir = SymbolPathParser.get_default_cache_dir()
        assert cache_dir is not None
        assert len(cache_dir) > 0
        # Should be in user's home directory
        assert os.path.expanduser("~") in cache_dir or "LOCALAPPDATA" in os.environ


class TestSymbolServerClient(unittest.TestCase):
    """Test SymbolServerClient functionality."""

    def test_build_symbol_url(self):
        """Test URL construction for symbol server."""
        client = SymbolServerClient()
        info = PDBInfo(
            pdb_name="kernel32.pdb",
            guid="AABBCCDD11223344AABBCCDD11223344",
            age=1,
            signature_id="AABBCCDD11223344AABBCCDD112233441",
        )

        url = client._build_symbol_url("https://msdl.microsoft.com/download/symbols", info)

        assert (
            url
            == "https://msdl.microsoft.com/download/symbols/kernel32.pdb/AABBCCDD11223344AABBCCDD112233441/kernel32.pdb"
        )

    def test_build_symbol_url_strips_trailing_slash(self):
        """Test that trailing slash is removed from server URL."""
        client = SymbolServerClient()
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        url = client._build_symbol_url("https://server.com/symbols/", info)

        assert not url.startswith("https://server.com/symbols//")
        assert "/test.pdb/ABC1/test.pdb" in url

    @patch("urllib.request.urlopen")
    def test_try_download_success(self, mock_urlopen):
        """Test successful download."""
        mock_response = MagicMock()
        mock_response.read.side_effect = [b"PDB file content", b""]
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = SymbolServerClient()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            dest_path = f.name

        try:
            result = client._try_download("https://example.com/test.pdb", dest_path)
            assert result is True
            assert os.path.exists(dest_path)
            with open(dest_path, "rb") as f:
                assert f.read() == b"PDB file content"
        finally:
            if os.path.exists(dest_path):
                os.unlink(dest_path)

    @patch("urllib.request.urlopen")
    def test_try_download_404(self, mock_urlopen):
        """Test handling of 404 response."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(url="", code=404, msg="Not Found", hdrs={}, fp=None)

        client = SymbolServerClient()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            dest_path = f.name

        try:
            result = client._try_download("https://example.com/nonexistent.pdb", dest_path)
            assert result is False
        finally:
            if os.path.exists(dest_path):
                os.unlink(dest_path)

    @patch("urllib.request.urlopen")
    def test_try_download_network_error(self, mock_urlopen):
        """Test handling of network errors."""
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        client = SymbolServerClient()

        result = client._try_download("https://example.com/test.pdb", "/tmp/test.pdb")
        assert result is False

    @patch("urllib.request.urlopen")
    def test_try_download_with_progress_callback(self, mock_urlopen):
        """Test that progress callback receives download progress."""
        mock_response = MagicMock()
        mock_response.headers.get.return_value = "1000"  # Content-Length
        mock_response.read.side_effect = [b"a" * 500, b"b" * 500, b""]
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = SymbolServerClient()
        progress_calls = []

        def progress_callback(downloaded, total):
            progress_calls.append((downloaded, total))
            return True  # Continue downloading

        with tempfile.NamedTemporaryFile(delete=False) as f:
            dest_path = f.name

        try:
            result = client._try_download(
                "https://example.com/test.pdb", dest_path, progress_callback=progress_callback
            )
            assert result is True
            assert len(progress_calls) == 2
            assert progress_calls[0] == (500, 1000)
            assert progress_calls[1] == (1000, 1000)
        finally:
            if os.path.exists(dest_path):
                os.unlink(dest_path)

    @patch("urllib.request.urlopen")
    def test_try_download_cancelled_by_callback(self, mock_urlopen):
        """Test that download can be cancelled via progress_callback."""
        mock_response = MagicMock()
        mock_response.headers.get.return_value = "2000"  # Content-Length
        mock_response.read.side_effect = [b"a" * 500, b"b" * 500, b"c" * 500, b"d" * 500, b""]
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = SymbolServerClient()
        progress_calls = []

        def progress_callback(downloaded, total):
            progress_calls.append((downloaded, total))
            # Cancel after 1000 bytes
            return downloaded < 1000

        with tempfile.NamedTemporaryFile(delete=False) as f:
            dest_path = f.name

        try:
            with self.assertRaises(DownloadCancelledError):
                client._try_download("https://example.com/test.pdb", dest_path, progress_callback=progress_callback)
            # Should have been called twice (500, 1000) before cancellation
            assert len(progress_calls) == 2
            # Partial file should be cleaned up
            assert not os.path.exists(dest_path)
        finally:
            if os.path.exists(dest_path):
                os.unlink(dest_path)

    @patch("urllib.request.urlopen")
    def test_download_pdb_with_confirm_callback_allows(self, mock_urlopen):
        """Test confirm_callback allowing download."""
        mock_response = MagicMock()
        mock_response.headers.get.return_value = None
        mock_response.read.side_effect = [b"PDB content", b""]
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = SymbolServerClient()
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")
        confirmed_urls = []

        def confirm_callback(url):
            confirmed_urls.append(url)
            return True  # Allow download

        with tempfile.TemporaryDirectory() as tmpdir:
            result = client.download_pdb(
                "https://server.com", info, cache_path=tmpdir, confirm_callback=confirm_callback
            )

            assert result is not None
            assert len(confirmed_urls) == 1
            assert "test.pdb" in confirmed_urls[0]

    @patch("urllib.request.urlopen")
    def test_download_pdb_with_confirm_callback_denies(self, mock_urlopen):
        """Test confirm_callback denying download."""
        client = SymbolServerClient()
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")
        confirmed_urls = []

        def confirm_callback(url):
            confirmed_urls.append(url)
            return False  # Deny all downloads

        result = client.download_pdb("https://server.com", info, confirm_callback=confirm_callback)

        # Should have tried both URLs (.pdb and .pd_)
        assert len(confirmed_urls) == 2
        assert result is None
        # urlopen should never have been called
        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_download_pdb_with_progress_callback(self, mock_urlopen):
        """Test progress_callback during download_pdb."""
        mock_response = MagicMock()
        mock_response.headers.get.return_value = "100"
        mock_response.read.side_effect = [b"x" * 100, b""]
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = SymbolServerClient()
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")
        progress_calls = []

        def progress_callback(downloaded, total):
            progress_calls.append((downloaded, total))
            return True

        with tempfile.TemporaryDirectory() as tmpdir:
            result = client.download_pdb(
                "https://server.com", info, cache_path=tmpdir, progress_callback=progress_callback
            )

            assert result is not None
            assert len(progress_calls) == 1
            assert progress_calls[0] == (100, 100)


class TestSymbolResolver(unittest.TestCase):
    """Test SymbolResolver functionality."""

    def test_init_with_explicit_path(self):
        """Test initialization with explicit symbol path."""
        resolver = SymbolResolver("srv*https://server.com", search_microsoft_symserver=False)
        assert resolver.symbol_path_str == "srv*https://server.com"
        assert len(resolver.entries) == 1

    def test_init_with_explicit_path_no_microsoft_symserver(self):
        """Test initialization with explicit symbol path but no Microsoft symserver."""
        resolver = SymbolResolver("srv*https://server.com", download_symbols=True, search_microsoft_symserver=True)
        assert resolver.symbol_path_str == "srv*https://server.com"
        assert len(resolver.entries) == 2
        assert resolver.entries[1].server_url == "https://msdl.microsoft.com/download/symbols"

    def test_init_reads_environment(self):
        """Test that resolver reads from environment if no path provided."""
        with patch.dict(os.environ, {"_NT_SYMBOL_PATH": "srv*https://env-server.com"}):
            resolver = SymbolResolver()
            assert resolver.symbol_path_str == "srv*https://env-server.com"

    def test_init_prefers_nt_symbol_path(self):
        """Test that _NT_SYMBOL_PATH takes precedence over SYMBOL_PATH."""
        with patch.dict(
            os.environ, {"_NT_SYMBOL_PATH": "srv*https://nt-server.com", "SYMBOL_PATH": "srv*https://other-server.com"}
        ):
            resolver = SymbolResolver()
            assert "nt-server.com" in resolver.symbol_path_str

    def test_search_local_store_flat_layout(self):
        """Test searching local store with flat layout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a PDB file in flat layout
            pdb_path = os.path.join(tmpdir, "test.pdb")
            with open(pdb_path, "wb") as f:
                f.write(b"PDB content")

            resolver = SymbolResolver("")
            info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

            result = resolver._search_local_store(tmpdir, info)
            assert result == pdb_path

    def test_search_local_store_symbol_store_layout(self):
        """Test searching local store with symbol store layout."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create symbol store structure: root/pdbname/signature/pdbname
            store_path = os.path.join(tmpdir, "test.pdb", "ABC1")
            os.makedirs(store_path)
            pdb_path = os.path.join(store_path, "test.pdb")
            with open(pdb_path, "wb") as f:
                f.write(b"PDB content")

            resolver = SymbolResolver("")
            info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

            result = resolver._search_local_store(tmpdir, info)
            assert result == pdb_path

    def test_search_local_store_not_found(self):
        """Test that search returns None when PDB not found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolver = SymbolResolver("")
            info = PDBInfo(pdb_name="nonexistent.pdb", guid="ABC", age=1, signature_id="ABC1")

            result = resolver._search_local_store(tmpdir, info)
            assert result is None

    def test_find_pdb_searches_all_entries(self):
        """Test that find_pdb searches through all symbol path entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create PDB in second local path
            pdb_dir = os.path.join(tmpdir, "second")
            os.makedirs(pdb_dir)
            pdb_path = os.path.join(pdb_dir, "test.pdb")
            with open(pdb_path, "wb") as f:
                f.write(b"PDB content")

            first_dir = os.path.join(tmpdir, "first")
            os.makedirs(first_dir)

            resolver = SymbolResolver(f"{first_dir};{pdb_dir}")
            info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

            result = resolver.find_pdb(info)
            assert result == pdb_path

    @patch.object(SymbolServerClient, "download_pdb")
    def test_find_pdb_download_disabled_by_default(self, mock_download):
        """Test that find_pdb does not download when download_symbols is False."""
        mock_download.return_value = "https://server.com/test.pdb"

        resolver = SymbolResolver("srv*https://server.com", search_microsoft_symserver=False)
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        result = resolver.find_pdb(info)
        assert result is None
        mock_download.assert_not_called()

    def test_find_pdb_download_disabled_by_confirm_callback(self):
        """Test that find_pdb does not download when the confirm callback returns False."""
        confirm_called = {"called": False}

        def confirm_callback(url) -> bool:
            confirm_called["called"] = True
            assert url.startswith("https://server.com/")
            return False

        resolver = SymbolResolver("srv*https://server.com", download_symbols=True, search_microsoft_symserver=False)
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        result = resolver.find_pdb(info, confirm_callback=confirm_callback)
        assert confirm_called["called"] is True
        assert result is None

    @patch.object(SymbolServerClient, "download_pdb")
    def test_find_pdb_downloads_from_server(self, mock_download):
        """Test that find_pdb downloads from server when not in cache."""
        mock_download.return_value = "/tmp/downloaded.pdb"

        resolver = SymbolResolver("srv*https://server.com", download_symbols=True, search_microsoft_symserver=False)
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        result = resolver.find_pdb(info)

        assert result == "/tmp/downloaded.pdb"
        mock_download.assert_called_once()

    @patch.object(SymbolServerClient, "download_pdb")
    def test_find_pdb_checks_cache_before_download(self, mock_download):
        """Test that cached PDB is used instead of downloading."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create cached PDB
            cache_dir = os.path.join(tmpdir, "test.pdb", "ABC1")
            os.makedirs(cache_dir)
            cached_pdb = os.path.join(cache_dir, "test.pdb")
            with open(cached_pdb, "wb") as f:
                f.write(b"cached PDB")

            resolver = SymbolResolver(f"srv*{tmpdir}*https://server.com")
            info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

            result = resolver.find_pdb(info)

            assert result == cached_pdb
            mock_download.assert_not_called()

    @patch.object(SymbolServerClient, "download_pdb")
    def test_find_pdb_passes_confirm_callback(self, mock_download):
        """Test that find_pdb passes confirm_callback to download_pdb."""
        mock_download.return_value = "/tmp/downloaded.pdb"

        resolver = SymbolResolver("srv*https://server.com", download_symbols=True, search_microsoft_symserver=False)
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        def confirm_callback(url):
            return True

        result = resolver.find_pdb(info, confirm_callback=confirm_callback)

        assert result == "/tmp/downloaded.pdb"
        mock_download.assert_called_once()
        # Check that confirm_callback was passed
        call_kwargs = mock_download.call_args.kwargs
        assert call_kwargs["confirm_callback"] is confirm_callback

    @patch.object(SymbolServerClient, "download_pdb")
    def test_find_pdb_passes_progress_callback(self, mock_download):
        """Test that find_pdb passes progress_callback to download_pdb."""
        mock_download.return_value = "/tmp/downloaded.pdb"

        resolver = SymbolResolver("srv*https://server.com", download_symbols=True, search_microsoft_symserver=False)
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        def progress_callback(downloaded, total):
            return True

        result = resolver.find_pdb(info, progress_callback=progress_callback)

        assert result == "/tmp/downloaded.pdb"
        mock_download.assert_called_once()
        # Check that progress_callback was passed
        call_kwargs = mock_download.call_args.kwargs
        assert call_kwargs["progress_callback"] is progress_callback

    @patch.object(SymbolServerClient, "download_pdb")
    def test_find_pdb_propagates_cancellation_error(self, mock_download):
        """Test that DownloadCancelledError propagates from find_pdb."""
        mock_download.side_effect = DownloadCancelledError("Download cancelled")

        resolver = SymbolResolver("srv*https://server.com", download_symbols=True, search_microsoft_symserver=False)
        info = PDBInfo(pdb_name="test.pdb", guid="ABC", age=1, signature_id="ABC1")

        with self.assertRaises(DownloadCancelledError):
            resolver.find_pdb(info)


class TestSymbolPathEntry(unittest.TestCase):
    """Test SymbolPathEntry dataclass."""

    def test_local_entry(self):
        """Test creating local entry."""
        entry = SymbolPathEntry(entry_type="local", cache_path=None, server_url=None, local_path="/path/to/symbols")
        assert entry.entry_type == "local"
        assert entry.local_path == "/path/to/symbols"

    def test_srv_entry(self):
        """Test creating server entry."""
        entry = SymbolPathEntry(entry_type="srv", cache_path="/cache", server_url="https://server.com", local_path=None)
        assert entry.entry_type == "srv"
        assert entry.cache_path == "/cache"
        assert entry.server_url == "https://server.com"


if __name__ == "__main__":
    unittest.main()
