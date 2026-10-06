"""
Recovery of Go function symbols from the Go runtime's ``pclntab``.

Every binary produced by the Go linker carries this table (``.gopclntab`` on ELF,
``__gopclntab`` on Mach-O, embedded in ``.rdata`` or ``.text`` on PE). It lists the entry point
and the name of every function in the image, which makes it the only reliable source of
function starts for stripped Go binaries. Each entry (a ``_func`` record of the runtime) also
carries the size of the function's argument area and the offsets of its pc-value tables, from
which stack pointer deltas and line numbers are decoded on demand.

Every layout the Go linker has emitted since Go 1.2 is supported. They are described by the
``_Layout`` descriptors below (``_LAYOUT_GO12`` ... ``_LAYOUT_GO120``); in summary:

=========== ============ ============== ========== ==================== ===================== =================
layout      Go versions  magic          header     functab entry        ``_func`` after entry offsets relative
=========== ============ ============== ========== ==================== ===================== =================
go1.2       1.2 - 1.9    ``0xfffffffb`` nfunc only ``(uintptr, uintptr)`` 8 x int32, slot 4 is   table start
                                                                        ``frame`` (unused from
                                                                        1.5, ``0x1234567``)
go1.10      1.10 - 1.11  ``0xfffffffb`` nfunc only ``(uintptr, uintptr)`` 8 x int32, slot 4 is   table start
                                                                        ``funcID`` (uint32)
go1.12      1.12 - 1.15  ``0xfffffffb`` nfunc only ``(uintptr, uintptr)`` ``deferreturn`` in     table start
                                                                        slot 4, tail
                                                                        ``funcID u8, pad[2],
                                                                        nfuncdata u8``
go1.16      1.16 - 1.17  ``0xfffffffa`` 7 words    ``(uintptr, uintptr)`` + ``cuOffset``; 1.17   sub-tables
                                                                        turns a pad byte into
                                                                        ``flag``
go1.18      1.18 - 1.19  ``0xfffffff0`` 8 words    ``(uint32, uint32)``   ``entryoff`` from      sub-tables
                                                                        ``textStart``
go1.20      1.20 - 1.27  ``0xfffffff1`` 8 words    ``(uint32, uint32)``   + ``startLine``        sub-tables
=========== ============ ============== ========== ==================== ===================== =================

The three ``0xfffffffb`` layouts share one magic: the tail is told apart by how the records pack
(a ``funcID/pad/nfuncdata`` tail read as an ``int32`` yields an absurd ``nfuncdata``), and the
meaning of slot 4 by its values (``funcID`` numbers are small; ``frame`` sizes are not).

The header magic and the ``textStart`` field are deliberately not trusted: obfuscated binaries
clobber them, so the table is instead accepted or rejected on structural grounds and the record
layout is inferred from how the records pack. The pc-value encoding (zigzag varint value deltas,
pc deltas in units of ``minLC``) has not changed since Go 1.2.
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
    0xFFFFFFFB: (1, 2),
}

# ``_func.flag`` bits, from internal/abi.FuncFlag (stable since Go 1.17)
GO_FUNC_FLAG_TOP_FRAME = 1  # traceback stops here (goexit, mstart, ...)
GO_FUNC_FLAG_SP_WRITE = 2  # writes SP arbitrarily; the pcsp table cannot describe it
GO_FUNC_FLAG_ASM = 4  # implemented in assembly

# Section names that hold nothing but a pclntab. Before Go 1.18 the functab holds absolute addresses,
# so a PIE moves the table into relro: ``.data.rel.ro.gopclntab`` when Go links internally.
PCLNTAB_SECTION_NAMES = frozenset(
    {".gopclntab", "__gopclntab", ".go.pclntab", "__go_pclntab", ".data.rel.ro.gopclntab"}
)

# Sections a pclntab may be embedded in, searched by magic as a fallback. An external linker merges
# a PIE's ``.data.rel.ro.gopclntab`` into ``.data.rel.ro``.
_EMBEDDING_SECTION_NAMES = frozenset({".rdata", ".rodata", "__rodata", "__const", "__DATA_CONST", ".data.rel.ro"})

_VALID_PTR_SIZES = (4, 8)
_VALID_MIN_LC = (1, 2, 4)
_MAX_NAME_LEN = 4096
_NO_FUNCDATA = 0xFFFFFFFF
# what the Go 1.5 - 1.9 linkers wrote into the retired ``frame`` slot
_FRAME_SENTINEL = 0x1234567
# ``funcID`` is a small enumeration; a ``frame`` size above this cannot be one
_MAX_FUNC_ID = 0x40


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
                        Always 0 before Go 1.12, which has no such field.
    :ivar pcsp:         Offset in pctab of the stack pointer delta table, or 0. See :meth:`GoPclntab.pcsp`.
    :ivar pcfile:       Offset in pctab of the file index table, or 0. See :meth:`GoPclntab.pcfile`.
    :ivar pcln:         Offset in pctab of the line number table, or 0. See :meth:`GoPclntab.pcln`.
    :ivar npcdata:      Number of additional pcdata tables. See :meth:`GoPclntab.pcdata`.
    :ivar cu_offset:    Offset of the function's compilation unit in cutab. None before Go 1.16, which has
                        no compilation units: ``pcfile`` values index the file table directly.
    :ivar start_line:   Line number of the ``func`` keyword. None for binaries older than Go 1.20.
    :ivar func_id:      ``funcID`` marking special runtime functions; 0 for ordinary ones. The numbering is
                        that of ``internal/abi.FuncID`` (``cmd/internal/objabi.FuncID`` before 1.18) of
                        the Go version that built the binary. Always 0 before Go 1.10, which has no such field.
    :ivar flag:         ``GO_FUNC_FLAG_*`` bits. Always 0 before Go 1.17.
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
    cu_offset: int | None
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


class _Layout(NamedTuple):
    """
    How one generation of the Go linker lays the table out. See the module docstring for the summary
    and each ``_LAYOUT_*`` constant for the Go versions it covers.

    :ivar name:             Short name, e.g. ``"go1.12"``.
    :ivar version:          The ``layout_version`` tuple exposed by :class:`GoPclntab`.
    :ivar header_words:     Pointer-sized words after the 8-byte magic/pad/minLC/ptrSize header: 1 (nfunc
                            only), 7 (+ nfiles and five sub-table offsets) or 8 (+ textStart).
    :ivar entry_is_offset:  Function entries (in functab and ``_func``) are uint32 offsets from textStart
                            rather than absolute uintptrs.
    :ivar fields:           Names of the ``_func`` words after ``entry``, in order; ``_`` is ignored.
    :ivar fmt:              ``struct`` format of those words.
    :ivar table_relative:   Name, funcoff and pc-value offsets are relative to the table start and there
                            are no sub-tables (no funcnametab/cutab/filetab/pctab).
    :ivar funcdata_is_ptr:  funcdata entries after the pcdata offsets are pointer-sized and pointer-aligned
                            rather than uint32 offsets.
    """

    name: str
    version: tuple[int, int]
    header_words: int
    entry_is_offset: bool
    fields: tuple[str, ...]
    fmt: str
    table_relative: bool
    funcdata_is_ptr: bool


# Go 1.2 - 1.9. Introduced by the Go 1.2 pclntab redesign (golang.org/s/go12symtab); the runtime
# side is runtime/symtab.go (symtab.c in 1.2 - 1.3) and debug/gosym's go12 reader.
#   magic 0xfffffffb, then nfunc (uintptr) and the functab of nfunc (entry, funcoff) uintptr pairs
#   plus the end sentinel entry; a uint32 after it gives the filetab offset. The filetab starts with
#   nfiles, followed by nfiles uint32 name offsets (index 0 is unused: pcfile values start at 1).
#   funcoff, nameoff, pcsp/pcfile/pcln, the pcdata offsets and the filetab name offsets are all
#   relative to the table start; there is no pctab, funcnametab or cutab.
#   _func: entry uintptr; nameoff, args, frame, pcsp, pcfile, pcln, npcdata, nfuncdata int32. ``frame``
#   is the local frame size in 1.2 - 1.4 and the 0x1234567 sentinel from 1.5 (cmd/link's "This has
#   been removed"). funcdata follow the npcdata uint32s, pointer-aligned, as pointers.
_LAYOUT_GO12 = _Layout(
    "go1.2",
    (1, 2),
    1,
    False,
    ("name_off", "args", "_", "pcsp", "pcfile", "pcln", "npcdata", "nfuncdata"),
    "iiIIIIII",
    True,
    True,
)

# Go 1.10 - 1.11. Same table as go1.2; the retired ``frame`` slot now holds funcID (a uint32
# cmd/internal/objabi.FuncID, runtime/runtime2.go ``_func.funcID``). The tail is still ``nfuncdata int32``.
_LAYOUT_GO110 = _LAYOUT_GO12._replace(
    name="go1.10",
    version=(1, 10),
    fields=("name_off", "args", "func_id", "pcsp", "pcfile", "pcln", "npcdata", "nfuncdata"),
)

# Go 1.12 - 1.15. Same table as go1.2; slot 4 is now ``deferreturn uint32`` and the last word packs
# ``funcID uint8, _ [2]int8, nfuncdata uint8`` (runtime/runtime2.go of 1.12, ``funcID`` became a uint8).
_LAYOUT_GO112 = _Layout(
    "go1.12",
    (1, 12),
    1,
    False,
    ("name_off", "args", "deferreturn", "pcsp", "pcfile", "pcln", "npcdata", "func_id", "nfuncdata"),
    "iiIIIIIBxxB",
    True,
    True,
)

# Go 1.16 - 1.17. The Go 1.16 pclntab split (runtime/symtab.go ``pcHeader``): magic 0xfffffffa, then
#   nfunc, nfiles, funcnameOffset, cuOffset, filetabOffset, pctabOffset, pclnOffset (uintptrs). functab
#   entries are still (entry uintptr, funcoff uintptr) pairs, funcoff relative to the pcln sub-table;
#   nameoff is relative to funcnametab and the pc-value offsets to pctab. File names go through the
#   per-compilation-unit cutab: cutab[cuOffset + fileno] is an offset into filetab.
#   _func: entry uintptr; nameoff, args int32; deferreturn, pcsp, pcfile, pcln, npcdata, cuOffset
#   uint32; funcID uint8; then ``_ [2]byte, nfuncdata uint8`` in 1.16 and ``flag uint8, _ [1]byte,
#   nfuncdata uint8`` in 1.17 (the pad byte reads as flag 0 on 1.16). funcdata are pointers.
_LAYOUT_GO116 = _Layout(
    "go1.16",
    (1, 16),
    7,
    False,
    (
        "name_off",
        "args",
        "deferreturn",
        "pcsp",
        "pcfile",
        "pcln",
        "npcdata",
        "cu_offset",
        "func_id",
        "flag",
        "nfuncdata",
    ),
    "iiIIIIIIBBxB",
    False,
    True,
)

# Go 1.18 - 1.19. Magic 0xfffffff0; the header gains textStart after nfiles and function entries become
#   uint32 offsets from it, in the functab (uint32 pairs) and in ``_func.entryoff``. funcdata are uint32
#   offsets into the go:func.* symbol instead of pointers. Everything else is as in go1.16/1.17.
_LAYOUT_GO118 = _LAYOUT_GO116._replace(
    name="go1.18", version=(1, 18), header_words=8, entry_is_offset=True, funcdata_is_ptr=False
)

# Go 1.20 and later, verified through 1.27. Magic 0xfffffff1; ``startLine int32`` is inserted before
#   funcID (runtime/symtab.go ``_func``, mirrored by internal/abi.Func).
_LAYOUT_GO120 = _LAYOUT_GO118._replace(
    name="go1.20",
    version=(1, 20),
    fields=(
        "name_off",
        "args",
        "deferreturn",
        "pcsp",
        "pcfile",
        "pcln",
        "npcdata",
        "cu_offset",
        "start_line",
        "func_id",
        "flag",
        "nfuncdata",
    ),
    fmt="iiIIIIIIiBBxB",
)

_LAYOUTS = {
    layout.version: layout
    for layout in (_LAYOUT_GO12, _LAYOUT_GO110, _LAYOUT_GO112, _LAYOUT_GO116, _LAYOUT_GO118, _LAYOUT_GO120)
}

# Header readings to try per magic. The 0xfffffffb layouts share a header; the record tail picks
# between go1.12 and go1.10, and slot 4's values between go1.10 and go1.2.
_MAGIC_LAYOUTS = {
    0xFFFFFFF1: (_LAYOUT_GO120,),
    0xFFFFFFF0: (_LAYOUT_GO118,),
    0xFFFFFFFA: (_LAYOUT_GO116,),
    0xFFFFFFFB: (_LAYOUT_GO112,),
}
# with the magic clobbered, every header shape is tried
_UNKNOWN_MAGIC_LAYOUTS = (_LAYOUT_GO120, _LAYOUT_GO116, _LAYOUT_GO112)


def _record_fmt(layout: _Layout, ptr_size: int) -> str:
    entry = "I" if layout.entry_is_offset or ptr_size == 4 else "Q"
    return entry + layout.fmt


class _Header(NamedTuple):
    magic: int
    min_lc: int
    ptr_size: int
    layout: _Layout
    nfunc: int
    text_start: int  # 0 for layouts without the field
    functab_off: int  # where the (entry, funcoff) pairs start
    func_base: int  # what funcoff is relative to
    funcname_off: int
    cutab_off: int
    filetab_off: int
    pctab_off: int
    pctab_end: int


class GoPclntab:
    """
    A parsed Go pclntab.

    :ivar magic:            The raw magic word. May be garbage: it is not used for validation.
    :ivar min_lc:           Minimum instruction length of the target architecture.
    :ivar ptr_size:         Pointer size, in bytes.
    :ivar text_start:       The base the function entry offsets are relative to, after recovery.
    :ivar functions:        The function table, sorted by address.
    :ivar layout_version:   The Go version whose table layout was used: (1, 2), (1, 10), (1, 12), (1, 16),
                            (1, 18) or (1, 20). See the module docstring for the version each covers.
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
        "_table_relative",
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
        layout = _LAYOUTS[layout_version]
        self._func_size = struct.calcsize("<" + _record_fmt(layout, ptr_size))
        self._table_relative = layout.table_relative
        self._addrs: list[int] | None = None

    def __repr__(self):
        return f"<GoPclntab: {len(self.functions)} functions, text at {self.text_start:#x}>"

    @property
    def go_version(self) -> tuple[int, int] | None:
        """
        The oldest Go version that emits this table layout, or None if the magic is not a known one.
        """
        return self.layout_version if self.magic in GO_PCLNTAB_MAGICS else None

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
        layout = header.layout
        nfunc, ptr_size = header.nfunc, header.ptr_size

        # nfunc pairs of (entry, funcoff), then one final entry marking the end of the last function.
        if layout.entry_is_offset:
            text_start = header.text_start
            if text_start == 0 or (is_text_addr is not None and not is_text_addr(text_start)):
                if text_start_fallback is None:
                    log.warning("gopclntab: textStart %#x is not code and there is no fallback", text_start)
                    return None
                log.debug("gopclntab: textStart %#x is not code, using %#x instead", text_start, text_start_fallback)
                text_start = text_start_fallback
            entries = struct.unpack_from(f"{endness}{2 * nfunc + 1}I", data, header.functab_off)
        else:
            entries = struct.unpack_from(
                f"{endness}{2 * nfunc + 1}{'Q' if ptr_size == 8 else 'I'}", data, header.functab_off
            )
            text_start = 0
        entry_offs = entries[0::2]
        func_offs = entries[1::2]
        if any(a >= b for a, b in zip(entry_offs, entry_offs[1:])):
            log.debug("gopclntab: function entry offsets are not monotonically increasing")
            return None
        if not layout.entry_is_offset:
            if is_text_addr is not None and not is_text_addr(entry_offs[0]):
                log.debug("gopclntab: first function entry %#x is not code", entry_offs[0])
                return None
            text_start = entry_offs[0]

        known = header.magic in GO_PCLNTAB_MAGICS
        if layout.header_words == 1:
            # same header for three record shapes: go1.12 (funcID/pad/nfuncdata tail) or go1.10 (int32 tail)
            layout = _infer_packing(
                data, endness, ptr_size, header.func_base, func_offs, (_LAYOUT_GO112, _LAYOUT_GO110)
            )
            if layout is None:
                if not known:
                    return None
                log.debug("gopclntab: cannot infer the _func tail from the record sizes, assuming Go 1.12")
                layout = _LAYOUT_GO112
        elif not known and layout.header_words == 8:
            layout = _infer_packing(
                data, endness, ptr_size, header.func_base, func_offs, (_LAYOUT_GO120, _LAYOUT_GO118)
            )
            if layout is None:
                log.debug("gopclntab: cannot infer the _func layout from the record sizes, assuming Go 1.20")
                layout = _LAYOUT_GO120

        fmt = endness + _record_fmt(layout, ptr_size)
        size = struct.calcsize(fmt)
        base = text_start if layout.entry_is_offset else 0
        records = []
        for i, func_off in enumerate(func_offs):
            rec_off = header.func_base + func_off
            if rec_off + size > len(data):
                log.debug("gopclntab: _func %d lies outside the table", i)
                return None
            fields = dict(zip(layout.fields, struct.unpack_from(fmt, data, rec_off)[1:]))
            name_off = header.funcname_off + fields["name_off"]
            if not header.funcname_off <= name_off < len(data):
                log.debug("gopclntab: name of function %d lies outside the table", i)
                return None
            end = data.find(b"\0", name_off, name_off + _MAX_NAME_LEN)
            if end == -1:
                log.debug("gopclntab: name of function %d is unterminated", i)
                return None
            name = data[name_off:end].decode("utf-8", "replace")
            records.append((base + entry_offs[i], entry_offs[i + 1] - entry_offs[i], name, fields, rec_off))

        if layout is _LAYOUT_GO110:
            # slot 4 holds funcIDs from 1.10 on, the frame size or the 0x1234567 sentinel before
            values = {fields["func_id"] for _, _, _, fields, _ in records}
            if _FRAME_SENTINEL in values or max(values, default=0) > _MAX_FUNC_ID:
                layout = _LAYOUT_GO12
                for _, _, _, fields, _ in records:
                    fields["func_id"] = 0

        functions = [
            GoFunction(
                addr,
                size,
                name,
                fields["args"],
                fields.get("deferreturn", 0),
                fields["pcsp"],
                fields["pcfile"],
                fields["pcln"],
                fields["npcdata"],
                fields.get("cu_offset"),
                fields.get("start_line"),
                fields.get("func_id", 0),
                fields.get("flag", 0),
                fields["nfuncdata"],
                rec_off,
            )
            for addr, size, name, fields, rec_off in records
        ]

        return cls(
            header.magic,
            header.min_lc,
            ptr_size,
            text_start,
            functions,
            layout_version=layout.version,
            data=data,
            endness=endness,
            pctab_off=header.pctab_off,
            pcln_off=header.pctab_end,
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

    def _file_name(self, cu_offset: int | None, idx: int) -> str | None:
        if idx < 0:
            return None
        data = self._data
        if self._table_relative:
            # filetab: nfiles, then table-relative name offsets indexed by the file number itself
            pos = self._filetab_off + 4 * idx
            start = 0
        else:
            # cutab maps (compilation unit, file index) to an offset into filetab
            pos = self._cutab_off + 4 * ((cu_offset or 0) + idx)
            start = self._filetab_off
        if pos + 4 > len(data):
            return None
        name_off = struct.unpack_from(self._endness + "I", data, pos)[0]
        if name_off == _NO_FUNCDATA:
            return None
        start += name_off
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
    Yield every structurally valid reading of the header. A known magic fixes the header shape; an
    unknown one tries the 1.18+ header (8 words, with textStart), then the 1.16 one (7 words), then
    the 1.2 one (nfunc only).
    """
    if len(data) < 16:
        return
    magic, _pad, min_lc, ptr_size = struct.unpack_from(endness + "IHBB", data, 0)
    if ptr_size not in _VALID_PTR_SIZES or min_lc not in _VALID_MIN_LC or _pad != 0:
        return
    for layout in _MAGIC_LAYOUTS.get(magic, _UNKNOWN_MAGIC_LAYOUTS):
        header = _parse_header_words(data, endness, magic, min_lc, ptr_size, layout)
        if header is not None:
            yield header


def _parse_header_words(
    data: bytes, endness: str, magic: int, min_lc: int, ptr_size: int, layout: _Layout
) -> _Header | None:
    nwords = layout.header_words
    header_size = 8 + nwords * ptr_size
    if len(data) < header_size:
        return None
    size = len(data)
    words = struct.unpack_from(f"{endness}{nwords}{'Q' if ptr_size == 8 else 'I'}", data, 8)

    if nwords == 1:
        # nfunc, the functab, then a uint32 filetab offset; the filetab starts with nfiles
        (nfunc,) = words
        functab_end = header_size + (2 * nfunc + 1) * ptr_size
        if nfunc <= 0 or functab_end + 4 > size:
            return None
        filetab_off = struct.unpack_from(endness + "I", data, functab_end)[0]
        if not functab_end + 4 <= filetab_off <= size - 4:
            return None
        # nfiles counts its own word: file numbers start at 1
        nfiles = struct.unpack_from(endness + "I", data, filetab_off)[0]
        if nfiles == 0 or filetab_off + 4 * nfiles > size:
            return None
        return _Header(magic, min_lc, ptr_size, layout, nfunc, 0, header_size, 0, 0, 0, filetab_off, 0, size)

    if nwords == 8:
        nfunc, nfiles, text_start, *offsets = words
    else:
        nfunc, nfiles, *offsets = words
        text_start = 0

    # the five sub-tables follow the header in a fixed order and all live inside the table
    if offsets[0] < header_size or offsets[-1] >= size:
        return None
    if any(a > b for a, b in zip(offsets, offsets[1:])):
        return None
    # a function costs one functab pair plus a _func struct, a file name at least 2 bytes
    entry_size = 4 if layout.entry_is_offset else ptr_size
    if nfunc <= 0 or offsets[-1] + (2 * nfunc + 1) * entry_size > size:
        return None
    if nfiles * 2 > size:
        return None

    funcname_off, cutab_off, filetab_off, pctab_off, pcln_off = offsets
    return _Header(
        magic,
        min_lc,
        ptr_size,
        layout,
        nfunc,
        text_start,
        pcln_off,
        pcln_off,
        funcname_off,
        cutab_off,
        filetab_off,
        pctab_off,
        pcln_off,
    )


def _infer_packing(
    data: bytes,
    endness: str,
    ptr_size: int,
    func_base: int,
    func_offs: tuple[int, ...],
    candidates: tuple[_Layout, ...],
) -> _Layout | None:
    """
    Pick the record layout under which the first records pack: with the right ``nfuncdata`` a record
    plus its pcdata and funcdata arrays ends where the linker put the next thing. Since Go 1.16 that
    is the next record (after rounding up to the pointer size). Before 1.16 the records are interleaved
    with the name strings and pc-value tables, and the function's name is appended first (unless an
    earlier function already shares it), so ``nameoff`` points at the end instead. Returns the first
    candidate under which every sampled record fits (1.16+), or the one that fits most records (older
    layouts, where shared names are skipped), or None.
    """
    n = min(len(func_offs) - 1, 32)
    best, best_score = None, 0
    for layout in candidates:
        fmt = endness + _record_fmt(layout, ptr_size)
        size = struct.calcsize(fmt)
        name_at, npcdata_at, nfuncdata_at = (layout.fields.index(f) + 1 for f in ("name_off", "npcdata", "nfuncdata"))
        score = 0
        for i in range(n):
            rec_off = func_base + func_offs[i]
            if rec_off + size > len(data):
                break
            fields = struct.unpack_from(fmt, data, rec_off)
            end = func_offs[i] + size + 4 * fields[npcdata_at]
            nfuncdata = fields[nfuncdata_at]
            if layout.funcdata_is_ptr:
                if nfuncdata:
                    end = _align(end, ptr_size) + ptr_size * nfuncdata
            else:
                end += 4 * nfuncdata
            if layout.table_relative:
                score += fields[name_at] == end
            elif _align(end, ptr_size) == func_offs[i + 1]:
                score += 1
            else:
                break
        else:
            if not layout.table_relative:
                return layout
        if layout.table_relative and score > best_score:
            best, best_score = layout, score
    return best


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


#
# Backend integration
#


def _read_section(backend: Backend, section) -> bytes | None:
    try:
        if section.memsize == 0 or section.only_contains_uninitialized_data:
            return None
        return backend.memory.load(AT.from_mva(section.vaddr, backend).to_rva(), section.memsize)
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
    # GoPclntab.parse decide whether what follows is really a table. PEs from Go linkers before 1.12
    # have no .rdata at all and keep the table in .text.
    if not embedding:
        embedding = [sec for sec in backend.sections if sec.name == ".text"]
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
    Find and parse the Go pclntab of an already-loaded object. Returns None if there is none. Addresses
    are read as the object's memory holds them, so after relocation a PIE's come out rebased.
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
