"""
Recovery of Go function symbols from the Go runtime's ``pclntab``.

Every binary produced by the Go linker carries this table (``.gopclntab`` on ELF,
``__gopclntab`` on Mach-O, embedded in ``.rdata`` on PE). It lists the entry point and the
name of every function in the image, which makes it the only reliable source of function
starts for stripped Go binaries. Each entry (a ``_func`` record of the runtime) also carries
the size of the function's argument area and the offsets of its pc-value tables, from which
stack pointer deltas and line numbers are decoded on demand.

The Go 1.16 (magic ``0xfffffffa``), 1.18 (``0xfffffff0``) and 1.20 (``0xfffffff1``) layouts
are supported. The header magic and the ``textStart`` field are deliberately not trusted:
obfuscated binaries clobber them, so the table is instead accepted or rejected on structural
grounds and the record layout is inferred from how the records pack.
"""

from __future__ import annotations

import logging
import struct
from bisect import bisect_right
from typing import TYPE_CHECKING, NamedTuple

from cle.address_translator import AT

from .symbol import Symbol, SymbolType

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from .backend import Backend

log = logging.getLogger(name=__name__)

__all__ = [
    "GO_FUNC_FLAG_ASM",
    "GO_FUNC_FLAG_SP_WRITE",
    "GO_FUNC_FLAG_TOP_FRAME",
    "GoFunction",
    "GoPclntab",
    "GoSymbol",
    "load_gopclntab",
    "register_gopclntab_symbols",
]

# magic -> minimum Go version that emits it
GO_PCLNTAB_MAGICS = {
    0xFFFFFFF1: (1, 20),
    0xFFFFFFF0: (1, 18),
    0xFFFFFFFA: (1, 16),
}

# ``_func.flag`` bits, from internal/abi.FuncFlag (stable since Go 1.17)
GO_FUNC_FLAG_TOP_FRAME = 1  # traceback stops here (goexit, mstart, ...)
GO_FUNC_FLAG_SP_WRITE = 2  # writes SP arbitrarily; the pcsp table cannot describe it
GO_FUNC_FLAG_ASM = 4  # implemented in assembly

# Section names that hold nothing but a pclntab.
PCLNTAB_SECTION_NAMES = frozenset({".gopclntab", "__gopclntab", ".go.pclntab", "__go_pclntab"})

# Sections a pclntab may be embedded in, searched by magic as a fallback.
_EMBEDDING_SECTION_NAMES = frozenset({".rdata", ".rodata", "__rodata", "__const", "__DATA_CONST"})

_VALID_PTR_SIZES = (4, 8)
_VALID_MIN_LC = (1, 2, 4)
_MAX_NAME_LEN = 4096
_NO_FUNCDATA = 0xFFFFFFFF


class GoFunction(NamedTuple):
    """
    One entry of the pclntab's function table: the runtime's ``_func`` record.

    :ivar addr:         Entry point of the function, as a linked virtual address.
    :ivar size:         Distance to the next function; includes inter-function padding.
    :ivar name:         Fully qualified Go name, e.g. ``net/http.(*Server).Serve``.
    :ivar args:         Size in bytes of the stack area for arguments and results (``_func.args``). For
                        register-ABI functions this is the spill area of the register arguments. It is
                        ``-0x80000000`` (``ArgsSizeUnknown``) for assembly functions without a Go declaration.
    :ivar deferreturn:  Offset from ``addr`` of the call to ``runtime.deferreturn``, or 0 if there is none.
    :ivar pcsp:         Offset in pctab of the stack pointer delta table, or 0. See :meth:`GoPclntab.pcsp`.
    :ivar pcfile:       Offset in pctab of the file index table, or 0. See :meth:`GoPclntab.pcfile`.
    :ivar pcln:         Offset in pctab of the line number table, or 0. See :meth:`GoPclntab.pcln`.
    :ivar npcdata:      Number of additional pcdata tables. See :meth:`GoPclntab.pcdata`.
    :ivar cu_offset:    Offset of the function's compilation unit in cutab.
    :ivar start_line:   Line number of the ``func`` keyword. None for binaries older than Go 1.20.
    :ivar func_id:      ``funcID`` marking special runtime functions; 0 for ordinary ones. The numbering is
                        that of ``internal/abi.FuncID`` of the Go version that built the binary.
    :ivar flag:         ``GO_FUNC_FLAG_*`` bits.
    :ivar nfuncdata:    Number of funcdata entries.
    :ivar func_off:     Offset of the ``_func`` record within the table.
    """

    addr: int
    size: int
    name: str
    args: int
    deferreturn: int
    pcsp: int
    pcfile: int
    pcln: int
    npcdata: int
    cu_offset: int
    start_line: int | None
    func_id: int
    flag: int
    nfuncdata: int
    func_off: int


class GoSymbol(Symbol):
    """
    A function symbol recovered from a Go pclntab.
    """

    def __init__(self, owner: Backend, name: str, relative_addr: int, size: int):
        super().__init__(owner, name, relative_addr, size, SymbolType.TYPE_FUNCTION)


class _FuncLayout(NamedTuple):
    """
    The fixed part of a ``_func`` record. It is followed by ``npcdata`` uint32 pctab offsets and
    ``nfuncdata`` funcdata references (uint32 offsets since 1.18, pointers before).
    """

    fmt: str
    size: int
    has_start_line: bool


def _func_layout(version: tuple[int, int], ptr_size: int) -> _FuncLayout:
    # entry is a uintptr in 1.16/1.17 and a uint32 offset from textStart since 1.18; then
    # nameOff args deferreturn pcsp pcfile pcln npcdata cuOffset [startLine] funcID flag pad nfuncdata
    entry = ("Q" if ptr_size == 8 else "I") if version < (1, 18) else "I"
    has_start_line = version >= (1, 20)
    fmt = entry + "iiIIIIII" + ("i" if has_start_line else "") + "BBxB"
    return _FuncLayout(fmt, struct.calcsize("<" + fmt), has_start_line)


class _Header(NamedTuple):
    magic: int
    min_lc: int
    ptr_size: int
    version: tuple[int, int]
    nfunc: int
    text_start: int  # 0 for 1.16 headers, which have no such field
    funcname_off: int
    cutab_off: int
    filetab_off: int
    pctab_off: int
    pcln_off: int


class GoPclntab:
    """
    A parsed Go pclntab.

    :ivar magic:            The raw magic word. May be garbage: it is not used for validation.
    :ivar min_lc:           Minimum instruction length of the target architecture.
    :ivar ptr_size:         Pointer size, in bytes.
    :ivar text_start:       The base the function entry offsets are relative to, after recovery.
    :ivar functions:        The function table, sorted by address.
    :ivar layout_version:   The Go version whose table layout was used: (1, 16), (1, 18) or (1, 20).
    """

    __slots__ = (
        "magic",
        "min_lc",
        "ptr_size",
        "text_start",
        "functions",
        "layout_version",
        "_data",
        "_endness",
        "_pctab",
        "_cutab_off",
        "_filetab_off",
        "_func_size",
        "_addrs",
    )

    def __init__(
        self,
        magic: int,
        min_lc: int,
        ptr_size: int,
        text_start: int,
        functions: list[GoFunction],
        layout_version: tuple[int, int] = (1, 20),
        data: bytes = b"",
        endness: str = "<",
        pctab_off: int = 0,
        pcln_off: int = 0,
        cutab_off: int = 0,
        filetab_off: int = 0,
    ):
        self.magic = magic
        self.min_lc = min_lc
        self.ptr_size = ptr_size
        self.text_start = text_start
        self.functions = functions
        self.layout_version = layout_version
        self._data = data
        self._endness = endness
        self._pctab = memoryview(data)[pctab_off:pcln_off]
        self._cutab_off = cutab_off
        self._filetab_off = filetab_off
        self._func_size = _func_layout(layout_version, ptr_size).size
        self._addrs: list[int] | None = None

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
        :param is_text_addr:        Predicate deciding whether an address points at code.
        """
        for header in _parse_headers(data, endness):
            tab = cls._parse_table(data, endness, header, text_start_fallback, is_text_addr)
            if tab is not None:
                return tab
        return None

    @classmethod
    def _parse_table(
        cls,
        data: bytes,
        endness: str,
        header: _Header,
        text_start_fallback: int | None,
        is_text_addr: Callable[[int], bool] | None,
    ) -> GoPclntab | None:
        version = header.version
        nfunc, pcln_off, ptr_size = header.nfunc, header.pcln_off, header.ptr_size

        # nfunc pairs of (entry, funcoff), then one final entry marking the end of the last function.
        # Entries are absolute pointers in 1.16/1.17 and uint32 offsets from textStart since 1.18.
        if version >= (1, 18):
            text_start = header.text_start
            if text_start == 0 or (is_text_addr is not None and not is_text_addr(text_start)):
                if text_start_fallback is None:
                    log.warning("gopclntab: textStart %#x is not code and there is no fallback", text_start)
                    return None
                log.debug("gopclntab: textStart %#x is not code, using %#x instead", text_start, text_start_fallback)
                text_start = text_start_fallback
            entries = struct.unpack_from(f"{endness}{2 * nfunc + 1}I", data, pcln_off)
        else:
            entries = struct.unpack_from(f"{endness}{2 * nfunc + 1}{'Q' if ptr_size == 8 else 'I'}", data, pcln_off)
            text_start = 0
        entry_offs = entries[0::2]
        func_offs = entries[1::2]
        if any(a >= b for a, b in zip(entry_offs, entry_offs[1:])):
            log.debug("gopclntab: function entry offsets are not monotonically increasing")
            return None
        if version < (1, 18):
            if is_text_addr is not None and not is_text_addr(entry_offs[0]):
                log.debug("gopclntab: first function entry %#x is not code", entry_offs[0])
                return None
            text_start = entry_offs[0]
        elif header.magic not in GO_PCLNTAB_MAGICS:
            version = _infer_layout_version(data, endness, ptr_size, pcln_off, func_offs)

        layout = _func_layout(version, ptr_size)
        fmt = endness + layout.fmt
        base = text_start if version >= (1, 18) else 0
        functions = []
        for i, func_off in enumerate(func_offs):
            rec_off = pcln_off + func_off
            if rec_off + layout.size > len(data):
                log.debug("gopclntab: _func %d lies outside the table", i)
                return None
            fields = struct.unpack_from(fmt, data, rec_off)
            name_off = header.funcname_off + fields[1]
            if not header.funcname_off <= name_off < len(data):
                log.debug("gopclntab: name of function %d lies outside the table", i)
                return None
            end = data.find(b"\0", name_off, name_off + _MAX_NAME_LEN)
            if end == -1:
                log.debug("gopclntab: name of function %d is unterminated", i)
                return None
            name = data[name_off:end].decode("utf-8", "replace")
            if not layout.has_start_line:
                fields = fields[:9] + (None,) + fields[9:]
            addr, size = base + entry_offs[i], entry_offs[i + 1] - entry_offs[i]
            functions.append(GoFunction(addr, size, name, *fields[2:], rec_off))

        return cls(
            header.magic,
            header.min_lc,
            ptr_size,
            text_start,
            functions,
            layout_version=version,
            data=data,
            endness=endness,
            pctab_off=header.pctab_off,
            pcln_off=pcln_off,
            cutab_off=header.cutab_off,
            filetab_off=header.filetab_off,
        )

    #
    # Lookups
    #

    def function_at(self, addr: int) -> GoFunction | None:
        """
        The function containing the linked address ``addr``, if any.
        """
        if self._addrs is None:
            self._addrs = [f.addr for f in self.functions]
        i = bisect_right(self._addrs, addr) - 1
        if i < 0:
            return None
        func = self.functions[i]
        return func if addr < func.addr + func.size else None

    #
    # pc-value tables, decoded on demand
    #

    def pcvalue(self, off: int) -> list[tuple[int, int]]:
        """
        Decode the pc-value table at offset ``off`` of pctab into ``(pc, value)`` pairs, where ``pc`` is
        an offset from the function's entry and ``value`` holds from there up to the next pair's ``pc``.
        An offset of 0 means "no table" and yields an empty list.

        The format is Go's: a zigzag varint value delta (the first one relative to -1) followed by an
        unsigned varint pc delta in units of ``min_lc``, terminated by a zero value delta.
        """
        if off <= 0:
            return []
        pctab = self._pctab
        min_lc = self.min_lc
        pos, pc, val = off, 0, -1
        out: list[tuple[int, int]] = []
        try:
            while True:
                uv, pos = _read_varint(pctab, pos)
                if uv == 0 and out:
                    break
                val += ~(uv >> 1) if uv & 1 else uv >> 1
                pc_delta, pos = _read_varint(pctab, pos)
                out.append((pc, val))
                pc += pc_delta * min_lc
        except (IndexError, ValueError):
            log.debug("gopclntab: malformed pc-value table at pctab offset %#x", off)
        return out

    def pcsp(self, func: GoFunction) -> list[tuple[int, int]]:
        """
        The stack pointer delta table of ``func``: ``(pc offset from entry, sp delta)`` pairs, the delta
        being how far SP has moved below its value at entry. Empty for assembly functions without one.
        """
        return self.pcvalue(func.pcsp)

    def sp_delta(self, func: GoFunction, addr: int) -> int | None:
        """
        The stack pointer delta in effect at the linked address ``addr`` of ``func``, or None if unknown.
        """
        off = addr - func.addr
        if not 0 <= off < func.size:
            return None
        delta = None
        for pc, value in self.pcsp(func):
            if pc > off:
                break
            delta = value
        return delta

    def pcln(self, func: GoFunction) -> list[tuple[int, int]]:
        """
        The line number table of ``func``: ``(pc offset from entry, line)`` pairs.
        """
        return self.pcvalue(func.pcln)

    def pcfile(self, func: GoFunction) -> list[tuple[int, str | None]]:
        """
        The source file table of ``func``: ``(pc offset from entry, file name)`` pairs.
        """
        return [(pc, self._file_name(func.cu_offset, idx)) for pc, idx in self.pcvalue(func.pcfile)]

    def pcdata(self, func: GoFunction, table: int) -> list[tuple[int, int]]:
        """
        Decode the ``table``-th pcdata table of ``func`` (indices are ``internal/abi.PCDATA_*``).
        """
        if not 0 <= table < func.npcdata:
            return []
        pos = func.func_off + self._func_size + 4 * table
        if pos + 4 > len(self._data):
            return []
        return self.pcvalue(struct.unpack_from(self._endness + "I", self._data, pos)[0])

    def _file_name(self, cu_offset: int, idx: int) -> str | None:
        # cutab maps (compilation unit, file index) to an offset into filetab
        if idx < 0:
            return None
        data = self._data
        pos = self._cutab_off + 4 * (cu_offset + idx)
        if pos + 4 > len(data):
            return None
        name_off = struct.unpack_from(self._endness + "I", data, pos)[0]
        if name_off == _NO_FUNCDATA:
            return None
        start = self._filetab_off + name_off
        end = data.find(b"\0", start, start + _MAX_NAME_LEN)
        if end == -1:
            return None
        return data[start:end].decode("utf-8", "replace")


def _read_varint(data, pos: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, pos
        shift += 7
        if shift > 28:
            raise ValueError("varint longer than 32 bits")


def _parse_headers(data: bytes, endness: str) -> Iterator[_Header]:
    """
    Yield every structurally valid reading of the header. A known magic fixes the layout; an unknown
    one tries the 1.18+ header (8 words, with textStart) before the 1.16 one (7 words).
    """
    if len(data) < 16:
        return
    magic, _pad, min_lc, ptr_size = struct.unpack_from(endness + "IHBB", data, 0)
    if ptr_size not in _VALID_PTR_SIZES or min_lc not in _VALID_MIN_LC or _pad != 0:
        return
    known = GO_PCLNTAB_MAGICS.get(magic)
    for version in (known,) if known is not None else ((1, 18), (1, 16)):
        header = _parse_header_words(data, endness, magic, min_lc, ptr_size, version)
        if header is not None:
            yield header


def _parse_header_words(
    data: bytes, endness: str, magic: int, min_lc: int, ptr_size: int, version: tuple[int, int]
) -> _Header | None:
    nwords = 8 if version >= (1, 18) else 7
    header_size = 8 + nwords * ptr_size
    if len(data) < header_size:
        return None
    words = struct.unpack_from(f"{endness}{nwords}{'Q' if ptr_size == 8 else 'I'}", data, 8)
    if version >= (1, 18):
        nfunc, nfiles, text_start, *offsets = words
    else:
        nfunc, nfiles, *offsets = words
        text_start = 0

    size = len(data)
    # the five sub-tables follow the header in a fixed order and all live inside the table
    if offsets[0] < header_size or offsets[-1] >= size:
        return None
    if any(a > b for a, b in zip(offsets, offsets[1:])):
        return None
    # a function costs one functab pair plus a _func struct, a file name at least 2 bytes
    entry_size = 4 if version >= (1, 18) else ptr_size
    if nfunc <= 0 or offsets[-1] + (2 * nfunc + 1) * entry_size > size:
        return None
    if nfiles * 2 > size:
        return None

    return _Header(magic, min_lc, ptr_size, version, nfunc, text_start, *offsets)


def _infer_layout_version(
    data: bytes, endness: str, ptr_size: int, pcln_off: int, func_offs: tuple[int, ...]
) -> tuple[int, int]:
    """
    Tell the 1.18 and 1.20 record layouts apart when the magic is unusable: with the right layout, a
    record plus its pcdata and funcdata arrays, rounded up to the pointer size, ends exactly where the
    next record starts.
    """
    n = min(len(func_offs) - 1, 16)
    for version in ((1, 20), (1, 18)):
        layout = _func_layout(version, ptr_size)
        fmt = endness + layout.fmt
        for i in range(n):
            rec_off = pcln_off + func_offs[i]
            if rec_off + layout.size > len(data):
                break
            fields = struct.unpack_from(fmt, data, rec_off)
            end = func_offs[i] + layout.size + 4 * (fields[7] + fields[-1])
            if (end + ptr_size - 1) & ~(ptr_size - 1) != func_offs[i + 1]:
                break
        else:
            return version
    log.debug("gopclntab: cannot infer the _func layout from the record sizes, assuming Go 1.20")
    return (1, 20)


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

    # PE and Mach-O bury the table in a generic read-only section, so find it by magic and let
    # GoPclntab.parse decide whether what follows is really a table.
    if not embedding:
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
