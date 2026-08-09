"""
Recovery of Go function symbols from the Go runtime's ``pclntab``.

Every binary produced by the Go linker carries this table (``.gopclntab`` on ELF,
``__gopclntab`` on Mach-O, embedded in ``.rdata`` on PE). It lists the entry point and the
name of every function in the image, which makes it the only reliable source of function
starts for stripped Go binaries.

Only the Go 1.18+ layouts (magic ``0xfffffff0`` and ``0xfffffff1``) are supported. The
header magic and the ``textStart`` field are deliberately not trusted: obfuscated binaries
clobber them, so the table is instead accepted or rejected on structural grounds.
"""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, NamedTuple

from cle.address_translator import AT

from .symbol import Symbol, SymbolType

if TYPE_CHECKING:
    from collections.abc import Callable

    from .backend import Backend

log = logging.getLogger(name=__name__)

__all__ = ["GoFunction", "GoPclntab", "GoSymbol", "load_gopclntab", "register_gopclntab_symbols"]

# magic -> minimum Go version that emits it
GO_PCLNTAB_MAGICS = {
    0xFFFFFFF1: (1, 20),
    0xFFFFFFF0: (1, 18),
}

# Section names that hold nothing but a pclntab.
PCLNTAB_SECTION_NAMES = frozenset({".gopclntab", "__gopclntab", ".go.pclntab", "__go_pclntab"})

# Sections a pclntab may be embedded in, searched by magic as a fallback.
_EMBEDDING_SECTION_NAMES = frozenset({".rdata", ".rodata", "__rodata", "__const", "__DATA_CONST"})

# Sections whose presence means "this was built by the Go toolchain".
_GO_MARKER_SECTION_NAMES = frozenset({".gosymtab", ".typelink", ".itablink", ".noptrdata", ".noptrbss"})

_VALID_PTR_SIZES = (4, 8)
_VALID_MIN_LC = (1, 2, 4)
_MAX_NAME_LEN = 4096


class GoFunction(NamedTuple):
    """
    One entry of the pclntab's function table.

    :ivar addr: Entry point of the function, as a linked virtual address.
    :ivar size: Distance to the next function; includes inter-function padding.
    :ivar name: Fully qualified Go name, e.g. ``net/http.(*Server).Serve``.
    """

    addr: int
    size: int
    name: str


class GoSymbol(Symbol):
    """
    A function symbol recovered from a Go pclntab.
    """

    def __init__(self, owner: Backend, name: str, relative_addr: int, size: int):
        super().__init__(owner, name, relative_addr, size, SymbolType.TYPE_FUNCTION)


class GoPclntab:
    """
    A parsed Go pclntab.

    :ivar magic:        The raw magic word. May be garbage: it is not used for validation.
    :ivar min_lc:       Minimum instruction length of the target architecture.
    :ivar ptr_size:     Pointer size, in bytes.
    :ivar text_start:   The base the function entry offsets are relative to, after recovery.
    :ivar functions:    The function table, sorted by address.
    """

    __slots__ = ("magic", "min_lc", "ptr_size", "text_start", "functions")

    def __init__(self, magic: int, min_lc: int, ptr_size: int, text_start: int, functions: list[GoFunction]):
        self.magic = magic
        self.min_lc = min_lc
        self.ptr_size = ptr_size
        self.text_start = text_start
        self.functions = functions

    def __repr__(self):
        return f"<GoPclntab: {len(self.functions)} functions, text at {self.text_start:#x}>"

    @property
    def go_version(self) -> tuple[int, int] | None:
        return GO_PCLNTAB_MAGICS.get(self.magic)

    @classmethod
    def parse(
        cls,
        data: bytes,
        endness: str = "<",
        text_start_fallback: int | None = None,
        is_text_addr: Callable[[int], bool] | None = None,
    ) -> GoPclntab | None:
        """
        Parse a pclntab out of ``data``, which must start at the table header.

        Returns None if ``data`` does not structurally look like a pclntab.

        :param data:                The bytes of the table.
        :param endness:             ``<`` or ``>``.
        :param text_start_fallback: Address to use when the header's ``textStart`` is unusable.
        :param is_text_addr:        Predicate deciding whether ``textStart`` points at code.
        """
        header = _parse_header(data, endness)
        if header is None:
            return None
        magic, min_lc, ptr_size, nfunc, text_start, funcname_off, pcln_off = header

        if text_start == 0 or (is_text_addr is not None and not is_text_addr(text_start)):
            if text_start_fallback is None:
                log.warning("gopclntab: textStart %#x is not code and there is no fallback", text_start)
                return None
            log.debug("gopclntab: textStart %#x is not code, using %#x instead", text_start, text_start_fallback)
            text_start = text_start_fallback

        # nfunc pairs of (entryoff, funcoff), then one final entryoff marking the end of the last function
        entries = struct.unpack_from(f"{endness}{2 * nfunc + 1}I", data, pcln_off)
        entry_offs = entries[0::2]
        func_offs = entries[1::2]
        if any(a >= b for a, b in zip(entry_offs, entry_offs[1:])):
            log.debug("gopclntab: function entry offsets are not monotonically increasing")
            return None

        functions = []
        for i, func_off in enumerate(func_offs):
            # the _func struct is entryOff uint32 followed by nameOff int32
            name_ptr = pcln_off + func_off + 4
            if name_ptr + 4 > len(data):
                log.debug("gopclntab: _func %d lies outside the table", i)
                return None
            name_off = funcname_off + struct.unpack_from(endness + "i", data, name_ptr)[0]
            if not funcname_off <= name_off < len(data):
                log.debug("gopclntab: name of function %d lies outside the table", i)
                return None
            end = data.find(b"\0", name_off, name_off + _MAX_NAME_LEN)
            if end == -1:
                log.debug("gopclntab: name of function %d is unterminated", i)
                return None
            name = data[name_off:end].decode("utf-8", "replace")
            functions.append(GoFunction(text_start + entry_offs[i], entry_offs[i + 1] - entry_offs[i], name))

        return cls(magic, min_lc, ptr_size, text_start, functions)


def _parse_header(data: bytes, endness: str) -> tuple[int, int, int, int, int, int, int] | None:
    """
    Validate and decode a pclntab header. Returns
    ``(magic, min_lc, ptr_size, nfunc, text_start, funcname_off, pcln_off)`` or None.

    The magic is decoded but never checked, so that binaries with a clobbered one still load.
    """
    if len(data) < 16:
        return None
    magic, _pad, min_lc, ptr_size = struct.unpack_from(endness + "IHBB", data, 0)
    if ptr_size not in _VALID_PTR_SIZES or min_lc not in _VALID_MIN_LC or _pad != 0:
        return None

    header_size = 8 + 8 * ptr_size
    if len(data) < header_size:
        return None
    word = endness + ("Q" if ptr_size == 8 else "I")
    nfunc, nfiles, text_start, funcname_off, cu_off, filetab_off, pctab_off, pcln_off = (
        struct.unpack_from(word, data, 8 + i * ptr_size)[0] for i in range(8)
    )

    size = len(data)
    # the five sub-tables follow the header in a fixed order and all live inside the table
    offsets = (funcname_off, cu_off, filetab_off, pctab_off, pcln_off)
    if offsets[0] < header_size or offsets[-1] >= size:
        return None
    if any(a > b for a, b in zip(offsets, offsets[1:])):
        return None
    # a function costs 8 bytes of functab plus a _func struct, a file name at least 2 bytes
    if nfunc <= 0 or pcln_off + (2 * nfunc + 1) * 4 > size:
        return None
    if nfiles * 2 > size:
        return None

    return magic, min_lc, ptr_size, nfunc, text_start, funcname_off, pcln_off


#
# Backend integration
#


def _read_section(backend: Backend, section) -> bytes | None:
    try:
        if section.memsize == 0 or section.only_contains_uninitialized_data:
            return None
        return backend.memory.load(AT.from_lva(section.vaddr, backend).to_rva(), section.memsize)
    except Exception:  # pylint: disable=broad-except
        return None


def _executable_sections(backend: Backend):
    return [sec for sec in backend.sections if sec.is_executable and sec.memsize > 0]


def _text_start_fallback(execs) -> int | None:
    """
    The vaddr of the section holding the executable code, used when ``textStart`` is unusable.
    """
    if not execs:
        return None
    for sec in execs:
        if sec.name in (".text", "__text"):
            return sec.vaddr
    return min(sec.vaddr for sec in execs)


def _looks_like_go(backend: Backend) -> bool:
    return any(sec.name in _GO_MARKER_SECTION_NAMES or sec.name.startswith(".go.") for sec in backend.sections)


def _find_pclntab_data(backend: Backend, endness: str):
    """
    Yield candidate ``bytes`` objects, each starting at a possible pclntab header.
    """
    embedding = []
    for section in backend.sections:
        if section.name in PCLNTAB_SECTION_NAMES:
            data = _read_section(backend, section)
            if data is not None:
                yield data
        elif section.name in _EMBEDDING_SECTION_NAMES and not section.is_executable:
            embedding.append(section)

    # PE and Mach-O bury the table in a generic read-only section; find it by magic. Only worth
    # doing when something else already says this is a Go binary.
    if not embedding or not _looks_like_go(backend):
        return
    magics = [struct.pack(endness + "I", magic) for magic in GO_PCLNTAB_MAGICS]
    for section in embedding:
        data = _read_section(backend, section)
        if data is None:
            continue
        for magic in magics:
            pos = data.find(magic)
            while pos != -1:
                yield data[pos:]
                pos = data.find(magic, pos + 4)


def load_gopclntab(backend: Backend) -> GoPclntab | None:
    """
    Find and parse the Go pclntab of an already-loaded object. Returns None if there is none.
    """
    if not backend.sections:
        return None
    endness = ">" if backend.arch is not None and backend.arch.memory_endness == "Iend_BE" else "<"

    execs: list = []

    def is_text_addr(addr: int) -> bool:
        return any(sec.contains_addr(addr) for sec in execs)

    fallback = None
    for i, data in enumerate(_find_pclntab_data(backend, endness)):
        if i == 0:
            execs = _executable_sections(backend)
            fallback = _text_start_fallback(execs)
        tab = GoPclntab.parse(data, endness, text_start_fallback=fallback, is_text_addr=is_text_addr)
        if tab is not None:
            return tab
    return None


def register_gopclntab_symbols(backend: Backend) -> GoPclntab | None:
    """
    Parse the object's Go pclntab, if it has one, and add a function symbol for every Go
    function that is not already covered by a symbol table.
    """
    try:
        tab = load_gopclntab(backend)
    except (struct.error, ValueError):
        log.warning("Failed to parse the Go pclntab of %s", backend.binary_basename, exc_info=True)
        return None
    if tab is None:
        return None

    covered = {sym.relative_addr for sym in backend.symbols if sym.size and sym.is_function}
    by_name = getattr(backend, "_symbols_by_name", None)
    added = 0
    for func in tab.functions:
        relative_addr = AT.from_lva(func.addr, backend).to_rva()
        if relative_addr in covered:
            continue
        symbol = GoSymbol(backend, func.name, relative_addr, func.size)
        backend.symbols.add(symbol)
        if by_name is not None and func.name and func.name not in by_name:
            by_name[func.name] = symbol
        added += 1

    log.info("Recovered %d Go functions from the pclntab of %s (%d new)", len(tab.functions), backend, added)
    return tab
