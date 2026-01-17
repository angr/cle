from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    import pefile

log = logging.getLogger(name=__name__)


class DownloadCancelledError(Exception):
    """Raised when a download is cancelled by the client."""

    pass


@dataclass
class PDBInfo:
    """Debug information extracted from PE file for PDB lookup."""

    pdb_name: str  # Original PDB filename from debug directory
    guid: str  # GUID as uppercase hex string (no dashes)
    age: int  # Age value
    signature_id: str  # Combined GUID + age for symbol server lookup

    @classmethod
    def from_pe(cls, pe: pefile.PE) -> PDBInfo | None:
        """Extract PDB info from PE debug directory."""
        if not hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            return None

        for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
            # Look for CodeView (type 2) entries - IMAGE_DEBUG_TYPE_CODEVIEW
            if debug_entry.struct.Type != 2:
                continue

            if not debug_entry.entry:
                continue

            # Check for RSDS signature (PDB 7.0 format)
            if hasattr(debug_entry.entry, "CvSignature"):
                cv_sig = debug_entry.entry.CvSignature
                # RSDS = 0x53445352
                if cv_sig == 0x53445352:
                    return cls._parse_rsds(debug_entry.entry)
                # NB10 = 0x3031424E (older PDB 2.0 format)
                elif cv_sig == 0x3031424E:
                    return cls._parse_nb10(debug_entry.entry)

        return None

    @classmethod
    def _parse_rsds(cls, entry) -> PDBInfo | None:
        """Parse RSDS (PDB 7.0) CodeView debug info."""
        try:
            # pefile provides Signature as a struct with Data1-Data4 components
            # or as Signature_Data1, etc. directly on entry
            if hasattr(entry, "Signature_Data1"):
                data1 = entry.Signature_Data1
                data2 = entry.Signature_Data2
                data3 = entry.Signature_Data3
                data4 = bytes(entry.Signature_Data4)
            else:
                return None

            # Build GUID: Data1 (4 bytes) + Data2 (2 bytes) + Data3 (2 bytes) + Data4 (8 bytes)
            guid = f"{data1:08X}{data2:04X}{data3:04X}{data4.hex().upper()}"

            age = entry.Age
            pdb_name = entry.PdbFileName.rstrip(b"\x00").decode("utf-8", errors="replace")
            pdb_name = os.path.basename(pdb_name.replace("\\", "/"))

            # Symbol server format: GUID + age (lowercase hex, no padding)
            signature_id = f"{guid}{age:x}"

            return cls(pdb_name=pdb_name, guid=guid, age=age, signature_id=signature_id)
        except (AttributeError, ValueError) as e:
            log.debug("Failed to parse RSDS debug info: %s", e)
            return None

    @classmethod
    def _parse_nb10(cls, entry) -> PDBInfo | None:
        """Parse NB10 (PDB 2.0) CodeView debug info."""
        try:
            # NB10 uses TimeDateStamp instead of GUID
            timestamp = entry.TimeDateStamp
            age = entry.Age
            pdb_name = entry.PdbFileName.rstrip(b"\x00").decode("utf-8", errors="replace")
            pdb_name = os.path.basename(pdb_name.replace("\\", "/"))

            # For NB10, signature_id uses timestamp instead of GUID
            guid = f"{timestamp:08X}"
            signature_id = f"{guid}{age:x}"

            return cls(pdb_name=pdb_name, guid=guid, age=age, signature_id=signature_id)
        except (AttributeError, ValueError) as e:
            log.debug("Failed to parse NB10 debug info: %s", e)
            return None


@dataclass
class SymbolPathEntry:
    """Represents a single entry in the symbol path."""

    entry_type: str  # 'local', 'srv', 'cache', 'symsrv'
    cache_path: str | None  # Local cache directory
    server_url: str | None  # Symbol server URL (for srv/symsrv types)
    local_path: str | None  # Direct local path (for local type)


class SymbolPathParser:
    """Parse _NT_SYMBOL_PATH format strings."""

    @classmethod
    def parse(cls, symbol_path: str) -> list[SymbolPathEntry]:
        """
        Parse symbol path string into list of entries.

        Format examples:
        - srv*C:\\cache*https://server - download from server, cache locally
        - srv*https://server - download without local cache
        - cache*C:\\cache - set cache for subsequent entries
        - C:\\local\\path - local directory
        - symsrv*symsrv.dll*C:\\cache*https://server - explicit DLL specification
        """
        if not symbol_path:
            return []

        entries = []
        current_cache = None  # Tracks cache* directive

        for entry_str in symbol_path.split(";"):
            entry_str = entry_str.strip()
            if not entry_str:
                continue

            parts = entry_str.split("*")
            first = parts[0].lower()

            if first == "cache":
                # cache*<path> - sets default cache for subsequent entries
                if len(parts) >= 2 and parts[1]:
                    current_cache = parts[1]
                else:
                    current_cache = cls.get_default_cache_dir()
                continue

            elif first == "srv":
                # srv*<cache>*<server> or srv*<server>
                entry = cls._parse_srv_entry(parts[1:], current_cache)
                if entry:
                    entries.append(entry)

            elif first == "symsrv":
                # symsrv*<dll>*<cache>*<server> or symsrv*<dll>*<server>
                # Skip the DLL name (parts[1]), treat rest like srv
                if len(parts) >= 2:
                    entry = cls._parse_srv_entry(parts[2:], current_cache)
                    if entry:
                        entries.append(entry)

            else:
                # Local path - check if it looks like a path
                if os.path.isabs(entry_str) or entry_str.startswith("\\\\") or entry_str.startswith("~"):
                    expanded = os.path.expanduser(entry_str)
                    entries.append(
                        SymbolPathEntry(entry_type="local", cache_path=None, server_url=None, local_path=expanded)
                    )

        return entries

    @classmethod
    def _parse_srv_entry(cls, parts: list[str], default_cache: str | None) -> SymbolPathEntry | None:
        """Parse srv* entry components."""
        if not parts:
            return None

        # Determine if we have cache*server or just server
        if len(parts) == 1:
            # srv*<server> - no explicit cache
            server = parts[0]
            cache = default_cache
        elif len(parts) >= 2:
            # srv*<cache>*<server> or srv**<server> (empty cache = default)
            if parts[0]:
                cache = os.path.expanduser(parts[0])
            else:
                cache = default_cache
            server = parts[1] if len(parts) > 1 else None
        else:
            return None

        # Handle additional downstream stores (cascading)
        # For simplicity, we take the last server URL
        if len(parts) > 2:
            server = parts[-1]

        if not server:
            return None

        return SymbolPathEntry(entry_type="srv", cache_path=cache, server_url=server, local_path=None)

    @classmethod
    def get_default_cache_dir(cls) -> str:
        """Get default symbol cache directory."""
        # Windows default: %LOCALAPPDATA%\dbg\sym
        if os.name == "nt":
            local_app_data = os.environ.get("LOCALAPPDATA", "")
            if local_app_data:
                return os.path.join(local_app_data, "dbg", "sym")

        # Fallback: ~/.symbols
        return os.path.join(os.path.expanduser("~"), ".symbols")


class SymbolServerClient:
    """HTTP client for downloading from symbol servers."""

    MICROSOFT_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
    DEFAULT_TIMEOUT = 30
    USER_AGENT = "Microsoft-Symbol-Server/10.0.0.0"

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def download_pdb(
        self,
        server_url: str,
        pdb_info: PDBInfo,
        cache_path: str | None = None,
        confirm_callback: Callable[[str], bool] | None = None,
        progress_callback: Callable[[int, int | None], bool] | None = None,
    ) -> str | None:
        """
        Download PDB from symbol server.

        URL format: <server>/<pdb_name>/<signature_id>/<pdb_name>
        Also tries: <server>/<pdb_name>/<signature_id>/<pdb_name[:-1]_> (compressed)

        Args:
            server_url: Base URL of the symbol server
            pdb_info: PDB information for the file to download
            cache_path: Optional path to cache downloaded files
            confirm_callback: Optional callback called with each URL before attempting download.
                             Should return True to proceed with download, False to skip this URL.
            progress_callback: Optional callback called during download with (bytes_downloaded, total_bytes).
                              total_bytes may be None if content-length is not available.
                              Should return True to continue, False to cancel the download.

        Returns:
            Path to downloaded file, or None if not found.

        Raises:
            DownloadCancelledError: If the download was cancelled via progress_callback.
        """
        # Build URLs to try
        base_url = self._build_symbol_url(server_url, pdb_info)

        # Try uncompressed first, then compressed
        urls_to_try = [
            (base_url, pdb_info.pdb_name),  # Uncompressed .pdb
        ]

        # Add compressed variant (.pd_)
        if pdb_info.pdb_name.lower().endswith(".pdb"):
            compressed_name = pdb_info.pdb_name[:-1] + "_"
            compressed_url = base_url[:-1] + "_"
            urls_to_try.append((compressed_url, compressed_name))

        for url, filename in urls_to_try:
            log.debug("Trying to download from: %s", url)

            # Check with confirm_callback if provided
            if confirm_callback is not None:
                if not confirm_callback(url):
                    log.debug("Download skipped by confirm_callback: %s", url)
                    continue

            # Determine destination
            if cache_path:
                dest_dir = os.path.join(cache_path, pdb_info.pdb_name, pdb_info.signature_id)
                os.makedirs(dest_dir, exist_ok=True)
                dest_path = os.path.join(dest_dir, filename)
            else:
                # Use temp directory if no cache
                dest_path = os.path.join(tempfile.gettempdir(), f"pdb_{pdb_info.signature_id}_{filename}")

            if self._try_download(url, dest_path, progress_callback):
                # Handle compressed files
                if filename.endswith("_"):
                    final_name = pdb_info.pdb_name
                    final_path = os.path.join(os.path.dirname(dest_path), final_name)
                    decompressed = self._decompress_cab(dest_path, final_path)
                    if decompressed:
                        return decompressed
                    # If decompression fails, continue to next URL
                    log.debug("Decompression failed, trying next URL")
                    continue
                return dest_path

        return None

    def _build_symbol_url(self, server_url: str, pdb_info: PDBInfo) -> str:
        """Build symbol server URL for PDB lookup."""
        # Ensure no trailing slash
        server_url = server_url.rstrip("/")

        # URL format: server/pdbname/signature/pdbname
        return f"{server_url}/{pdb_info.pdb_name}/{pdb_info.signature_id}/{pdb_info.pdb_name}"

    def _try_download(
        self,
        url: str,
        dest_path: str,
        progress_callback: Callable[[int, int | None], bool] | None = None,
    ) -> bool:
        """
        Attempt to download file from URL using urllib.

        Args:
            url: URL to download from
            dest_path: Local path to save the downloaded file
            progress_callback: Optional callback called during download with (bytes_downloaded, total_bytes).
                              total_bytes may be None if content-length is not available.
                              Should return True to continue, False to cancel the download.

        Returns:
            True if download was successful, False otherwise.

        Raises:
            DownloadCancelledError: If the download was cancelled via progress_callback.
        """
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": self.USER_AGENT,
                    "Accept": "*/*",
                },
            )

            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                # Get total size if available
                total_size = response.headers.get("Content-Length")
                total_size = int(total_size) if total_size else None

                bytes_downloaded = 0

                # Read in chunks to handle large files
                with open(dest_path, "wb") as f:
                    while True:
                        chunk = response.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_downloaded += len(chunk)

                        # Call progress callback if provided
                        if progress_callback is not None:
                            if not progress_callback(bytes_downloaded, total_size):
                                # Callback returned False, cancel download
                                log.debug("Download cancelled by progress_callback: %s", url)
                                # Clean up partial file
                                try:
                                    os.unlink(dest_path)
                                except OSError:
                                    pass
                                raise DownloadCancelledError(f"Download cancelled: {url}")

            log.debug("Successfully downloaded to: %s", dest_path)
            return True

        except urllib.error.HTTPError as e:
            if e.code == 404:
                log.debug("Symbol not found at: %s", url)
            else:
                log.debug("HTTP error downloading %s: %s", url, e)
            return False
        except urllib.error.URLError as e:
            log.debug("URL error downloading %s: %s", url, e.reason)
            return False
        except OSError as e:
            log.debug("IO error downloading %s: %s", url, e)
            return False

    def _decompress_cab(self, cab_path: str, dest_path: str) -> str | None:
        """
        Decompress CAB file (Microsoft's symbol compression format).

        Returns path to decompressed file, or None if decompression not available.
        """
        dest_dir = os.path.dirname(dest_path)

        # Try using cabextract (common on Linux)
        try:
            result = subprocess.run(
                ["cabextract", "-q", "-d", dest_dir, cab_path], capture_output=True, timeout=30
            )
            if result.returncode == 0 and os.path.exists(dest_path):
                log.debug("Decompressed CAB with cabextract: %s", dest_path)
                return dest_path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try using expand.exe (Windows)
        if os.name == "nt":
            try:
                result = subprocess.run(["expand", cab_path, dest_path], capture_output=True, timeout=30)
                if result.returncode == 0 and os.path.exists(dest_path):
                    log.debug("Decompressed CAB with expand: %s", dest_path)
                    return dest_path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        log.warning(
            "Could not decompress CAB file %s. Install cabextract (Linux) or ensure expand.exe is available (Windows).",
            cab_path,
        )
        return None


class SymbolResolver:
    """Main class for resolving PDB files from symbol path."""

    def __init__(self, symbol_path: str | None = None):
        """
        Initialize resolver.

        Args:
            symbol_path: Symbol path string. If None, reads from environment.
        """
        self.symbol_path = symbol_path if symbol_path is not None else self._get_symbol_path_from_env()
        self.entries = SymbolPathParser.parse(self.symbol_path) if self.symbol_path else []
        self.client = SymbolServerClient()

    @staticmethod
    def _get_symbol_path_from_env() -> str | None:
        """Read symbol path from environment variables."""
        return os.environ.get("_NT_SYMBOL_PATH") or os.environ.get("SYMBOL_PATH")

    def find_pdb(
        self,
        pdb_info: PDBInfo,
        binary_dir: str | None = None,
        confirm_callback: Callable[[str], bool] | None = None,
        progress_callback: Callable[[int, int | None], bool] | None = None,
    ) -> str | None:
        """
        Find PDB file using symbol path.

        Args:
            pdb_info: PDB information from PE file
            binary_dir: Directory of the PE binary (for relative searches)
            confirm_callback: Optional callback called with each URL before attempting download.
                             Should return True to proceed with download, False to skip this URL.
            progress_callback: Optional callback called during download with (bytes_downloaded, total_bytes).
                              total_bytes may be None if content-length is not available.
                              Should return True to continue, False to cancel the download.

        Returns:
            Path to PDB file, or None if not found

        Raises:
            DownloadCancelledError: If the download was cancelled via progress_callback.
        """
        log.debug("Searching for PDB: %s (signature: %s)", pdb_info.pdb_name, pdb_info.signature_id)

        for entry in self.entries:
            result = None

            if entry.entry_type == "local":
                result = self._search_local_store(entry.local_path, pdb_info)

            elif entry.entry_type == "srv":
                # Check cache first
                if entry.cache_path:
                    result = self._search_local_store(entry.cache_path, pdb_info)

                # Download from server if not in cache
                if result is None and entry.server_url:
                    result = self._search_symbol_server(
                        entry, pdb_info, confirm_callback=confirm_callback, progress_callback=progress_callback
                    )

            if result:
                log.info("Found PDB at: %s", result)
                return result

        log.debug("PDB not found in symbol path")
        return None

    def _search_local_store(self, local_path: str | None, pdb_info: PDBInfo) -> str | None:
        """
        Search local symbol store for matching PDB.

        Symbol store layout: <root>/<pdb_name>/<signature_id>/<pdb_name>
        """
        if not local_path or not os.path.exists(local_path):
            return None

        # Check symbol store layout: path/pdbname/signature/pdbname
        store_path = os.path.join(local_path, pdb_info.pdb_name, pdb_info.signature_id, pdb_info.pdb_name)
        if os.path.exists(store_path):
            return store_path

        # Check for compressed file (.pd_)
        if pdb_info.pdb_name.lower().endswith(".pdb"):
            compressed_name = pdb_info.pdb_name[:-1] + "_"
            compressed_path = os.path.join(local_path, pdb_info.pdb_name, pdb_info.signature_id, compressed_name)
            if os.path.exists(compressed_path):
                # Decompress and return
                final_path = os.path.join(local_path, pdb_info.pdb_name, pdb_info.signature_id, pdb_info.pdb_name)
                decompressed = self.client._decompress_cab(compressed_path, final_path)
                if decompressed:
                    return decompressed

        # Check flat layout (PDB directly in directory) - note: doesn't verify GUID/age
        flat_path = os.path.join(local_path, pdb_info.pdb_name)
        if os.path.exists(flat_path):
            log.debug("Found PDB in flat layout (unverified): %s", flat_path)
            return flat_path

        return None

    def _search_symbol_server(
        self,
        entry: SymbolPathEntry,
        pdb_info: PDBInfo,
        confirm_callback: Callable[[str], bool] | None = None,
        progress_callback: Callable[[int, int | None], bool] | None = None,
    ) -> str | None:
        """
        Search symbol server and optionally cache result.

        Args:
            entry: Symbol path entry containing server URL and cache path
            pdb_info: PDB information for the file to download
            confirm_callback: Optional callback called with each URL before attempting download.
                             Should return True to proceed with download, False to skip this URL.
            progress_callback: Optional callback called during download with (bytes_downloaded, total_bytes).
                              total_bytes may be None if content-length is not available.
                              Should return True to continue, False to cancel the download.

        Returns:
            Path to downloaded PDB file, or None if not found.

        Raises:
            DownloadCancelledError: If the download was cancelled via progress_callback.
        """
        return self.client.download_pdb(
            entry.server_url,
            pdb_info,
            entry.cache_path,
            confirm_callback=confirm_callback,
            progress_callback=progress_callback,
        )
