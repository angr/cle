from __future__ import annotations

import logging
import os
import struct
from collections import defaultdict
from typing import NamedTuple

import elftools

from cle.address_translator import AT
from cle.backends import register_backend
from cle.backends.blob import Blob
from cle.backends.region import Segment
from cle.errors import CLECompatibilityError, CLEError
from cle.memory import Clemory

from .elf import ELF

log = logging.getLogger(name=__name__)

# TODO: yall know struct.unpack_from exists, right? maybe even bitstream?

# Core note types are namespaced by the note's name, so a type number only identifies a struct
# together with the name of the kernel that wrote it.
CORE_NAMESPACE = "CORE"
# Linux writes the general purpose and floating point register sets under CORE and every other
# register set, the GDT entries among them, under its own name.
LINUX_NAMESPACE = "LINUX"
FREEBSD_NAMESPACE = "FreeBSD"
# NetBSD names its process-wide note "NetBSD-CORE" and its per-LWP notes "NetBSD-CORE@<lwpid>".
NETBSD_NAMESPACE_PREFIX = "NetBSD-CORE"

# The type of the Linux note holding a thread's GDT entries, in the LINUX namespace.
NT_386_TLS = 512


class RegisterSet(NamedTuple):
    """
    The layout of a general purpose register set as a kernel writes it into a core note: a struct
    format string without a byte order prefix, and the name of the register each of its fields
    holds. Fields that are not registers angr knows about are named "xxx".
    """

    fmt: str
    names: tuple[str, ...]

    @property
    def size(self):
        return struct.calcsize("<" + self.fmt)


class NetBSDRegisters(NamedTuple):
    """
    NetBSD's per-LWP register note: the type NetBSD gives the note, and the layout of the struct reg
    it carries.
    """

    note_type: int
    gregset: RegisterSet


class ELFCore(ELF):
    """
    Loader class for ELF core files.

    One key pain point when analyzing a core dump generated on a remote machine is that the paths to binaries are
    absolute (and may not exist or be the same on your local machine).

    Therefore, you can use the options ```remote_file_mapping`` to specify a ``dict`` mapping (easy if there are a small
    number of mappings) or ``remote_file_mapper`` to specify a function that accepts a remote file name and returns the
    local file name (useful if there are many mappings).

    If you specify both ``remote_file_mapping`` and ``remote_file_mapper``, ``remote_file_mapping`` is applied first,
    then the result is passed to ``remote_file_mapper``.

    :param executable:           Optional path to the main binary of the core dump. If not supplied, ELFCore will
                                 attempt to figure it out automatically from the core dump.
    :param remote_file_mapping:  Optional dict that maps specific file names in the core dump to other file names.
    :param remote_file_mapper:   Optional function that is used to map every file name in the core dump to whatever is
                                 returned from this function.
    """

    is_default = True  # Tell CLE to automatically consider using the ELFCore backend

    def __init__(self, *args, executable=None, remote_file_mapping=None, remote_file_mapper=None, **kwargs):
        super().__init__(*args, **kwargs)

        self.filename_lookup = []
        self.__current_thread = None
        self._threads = []
        self.auxv = {}
        self.pr_fname = None
        self._main_filepath = executable
        self._page_size = 0x1000  # a default page size, will be changed later by parsing notes
        self._main_object = None

        if remote_file_mapping is not None:
            self._remote_file_mapper = lambda x: remote_file_mapping.get(x, x)
        else:
            self._remote_file_mapper = lambda x: x

        if remote_file_mapper is not None:
            orig = self._remote_file_mapper
            self._remote_file_mapper = lambda x: remote_file_mapper(orig(x))

        self.__extract_note_info()

        self.__reload_children()

        self._remote_file_mapper = None

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        identstring = stream.read(0x1000)
        stream.seek(0)
        if identstring.startswith(b"\x7fELF"):
            if elftools.elf.elffile.ELFFile(stream).header["e_type"] == "ET_CORE":
                return True
            return False
        return False

    def __cycle_thread(self):
        if self.__current_thread is not None:
            self._threads.append(self.__current_thread)
        self.__current_thread = {}

    @property
    def threads(self):
        return list(range(len(self._threads)))

    def thread_registers(self, thread=None):
        if not self._threads:
            return {}
        if thread is None:
            thread = 0
        return self._threads[thread]["registers"]

    @staticmethod
    def __note_desc(note):
        return note.n_desc.encode("latin-1") if isinstance(note.n_desc, str) else note.n_desc

    def __extract_note_info(self):
        """
        All meaningful information about the process's state at crashtime is stored in the note segment.
        """
        for seg_readelf in self._reader.iter_segments():
            if seg_readelf.header.p_type == "PT_NOTE":
                for note in seg_readelf.iter_notes():
                    if note.n_name == CORE_NAMESPACE:
                        if note.n_type == "NT_PRSTATUS":
                            self.__cycle_thread()
                            self.__parse_prstatus(self.__note_desc(note))
                        elif note.n_type == "NT_PRPSINFO":
                            self.__parse_prpsinfo(note.n_desc)
                        elif note.n_type == "NT_AUXV":
                            self.__parse_auxv(self.__note_desc(note))
                        elif note.n_type == "NT_FILE":
                            self.__parse_files(note.n_desc)
                    elif note.n_name == LINUX_NAMESPACE:
                        if note.n_type == NT_386_TLS and self.arch.name == "X86":
                            self.__parse_x86_tls(self.__note_desc(note))
                    elif note.n_name == FREEBSD_NAMESPACE:
                        if note.n_type == "NT_PRSTATUS":
                            self.__cycle_thread()
                            self.__parse_freebsd_prstatus(self.__note_desc(note))
                    elif note.n_name is not None and note.n_name.startswith(NETBSD_NAMESPACE_PREFIX):
                        # NetBSD's NT_PRSTATUS is a struct netbsd_elfcore_procinfo, which holds no registers
                        # at all - those live in one PT_GETREGS note per LWP.
                        netbsd = netbsd_register_sets.get(self.arch.name)
                        if netbsd is None:
                            raise CLECompatibilityError(f"Architecture '{self.arch.name}' unsupported by ELFCore")
                        if note.n_type == netbsd.note_type:
                            self.__cycle_thread()
                            self.__parse_netbsd_regs(self.__note_desc(note), netbsd.gregset)
                    elif note.n_type == "NT_PRSTATUS":
                        log.warning("Don't know how to read the registers of a core note namespaced '%s'", note.n_name)

        self._replace_main_object_path()

        self.__cycle_thread()
        unparsed = sum(1 for thread in self._threads if "registers" not in thread)
        if unparsed:
            log.warning("Discarding %d thread(s) whose registers could not be parsed", unparsed)
            self._threads = [thread for thread in self._threads if "registers" in thread]

        if not self._threads:
            log.warning("Could not find thread info, cannot initialize registers")
        elif self.arch.name == "X86" and "segments" not in self._threads[0]:
            if "AT_RANDOM" in self.auxv:
                log.warning(
                    "This core dump does not contain TLS information. "
                    "threads will be matched to TLS regions via heuristics"
                )
                pointer_rand = self.auxv["AT_RANDOM"][4:8]
                all_locations = [
                    addr - 0x18
                    for addr in self.__dummy_clemory.find(pointer_rand)
                    if self.__dummy_clemory.unpack_word(addr - 0x18) == addr - 0x18
                ]
                # the heuristic is that generally threads are allocated with descending tls addresses
                for thread, loc in zip(self._threads, reversed(all_locations)):
                    thread["segments"] = {thread["registers"]["gs"] >> 3: (loc, 0xFFFFF, 0x51)}
            else:
                log.warning("This core dump does not contain TLS or auxv information. TLS information will be wrong.")
                for thread in self._threads:
                    thread["segments"] = {thread["registers"]["gs"] >> 3: (0, 0xFFFFFFFF, 0x51)}

    def _replace_main_object_path(self):
        """
        try to replace path of the main_object with the specified one
        """
        if not self._main_filepath or not self.filename_lookup:
            return

        # identify the original path and assuming pr_fname always exists
        matched = None
        for i, (a, b, c, fn) in enumerate(self.filename_lookup):
            if os.path.basename(fn).startswith(
                self.pr_fname
            ):  # pr_fname is defined to be the first 16 bytes of the executable name
                matched = fn
                break
        else:
            raise CLEError("Fail to find the main object, is this core dump malformed?")

        # replace the path
        for i, (a, b, c, fn) in enumerate(self.filename_lookup):
            if fn == matched:
                self.filename_lookup[i] = (a, b, c, self._main_filepath)

    @property
    def __dummy_clemory(self):
        dummy_clemory = Clemory(self.arch, root=True)
        dummy_clemory.add_backer(self.linked_base, self.memory)
        return dummy_clemory

    def __parse_prstatus(self, desc):
        """
        Parse out a Linux struct elf_prstatus, accumulating the general purpose register values.
        Supports AMD64, X86, ARM, AArch64, MIPS and MIPSEL at the moment.

        :param desc: the descriptor of a note of type NT_PRSTATUS in the CORE namespace.
        """

        # TODO: support all architectures angr supports
        arch_bytes = self.arch.bytes
        if arch_bytes == 4:
            fmt = "I"
        elif arch_bytes == 8:
            fmt = "Q"
        else:
            raise CLEError("Architecture must have a bitwidth of either 64 or 32")

        rnames = linux_register_names.get(self.arch.name)
        if rnames is None:
            raise CLECompatibilityError(f"Architecture '{self.arch.name}' unsupported by ELFCore")

        end = ">" if self.arch.memory_endness == "Iend_BE" else "<"

        # three ints and a short padded to an int, then two longs, four ints and four timevals,
        # then the registers and pr_fpvalid, and finally padding out to the struct's alignment
        prologue_size = 32 + 10 * arch_bytes
        struct_size = prologue_size + len(rnames) * arch_bytes + 4
        if not struct_size <= len(desc) < struct_size + arch_bytes:
            # the process ABI is not the one the core's ELF header implies - an x32 process dumped by an
            # x86-64 kernel, say, or a 32-bit MIPS process dumped by a 64-bit one
            log.warning(
                "Skipping a thread whose NT_PRSTATUS is %d bytes; a %s struct elf_prstatus is %d",
                len(desc),
                self.arch.name,
                struct_size,
            )
            return

        pos = 0

        def read_longs(n):
            fin = pos + n * arch_bytes
            return (fin, *struct.unpack(end + fmt * n, desc[pos:fin]))

        def read_ints(n):
            fin = pos + n * 4
            return (fin, *struct.unpack(end + "I" * n, desc[pos:fin]))

        def read_timeval():
            sec, usec = struct.unpack(end + fmt * 2, desc[pos : pos + 2 * arch_bytes])
            return (pos + 2 * arch_bytes, sec * 1000000 + usec)

        result = {}

        pos, result["si_signo"], result["si_code"], result["si_errno"] = read_ints(3)

        # this field is a short, but it's padded to an int
        (result["pr_cursig"],) = struct.unpack(end + "H", desc[pos : pos + 2])
        pos += 4

        pos, result["pr_sigpend"], result["pr_sighold"] = read_longs(2)

        pos, result["pr_pid"], result["pr_ppid"], result["pr_pgrp"], result["pr_sid"] = read_ints(4)

        pos, result["pr_utime_usec"] = read_timeval()
        pos, result["pr_stime_usec"] = read_timeval()
        pos, result["pr_cutime_usec"] = read_timeval()
        pos, result["pr_cstime_usec"] = read_timeval()

        pos, *regvals = read_longs(len(rnames))
        result["registers"] = dict(zip(rnames, regvals, strict=True))
        result["registers"].pop("xxx", None)

        pos, result["pr_fpvalid"] = read_ints(1)

        self.__current_thread.update(result)

    def __parse_freebsd_prstatus(self, desc):
        """
        Parse out a FreeBSD struct prstatus, accumulating the general purpose register values. It shares no
        prefix with the Linux struct of the same note type, but it is self-describing: its header carries
        the size of the whole struct and of the register set that follows it.

        :param desc: the descriptor of a note of type NT_PRSTATUS in the FreeBSD namespace.
        """

        end = ">" if self.arch.memory_endness == "Iend_BE" else "<"
        header_fmt = end + ("i4xQQQiii4x" if self.arch.bytes == 8 else "iIIIiii")
        header_size = struct.calcsize(header_fmt)

        gregset = freebsd_register_sets.get(self.arch.name)
        if gregset is None:
            raise CLECompatibilityError(f"Architecture '{self.arch.name}' unsupported by ELFCore")

        if len(desc) < header_size + gregset.size:
            log.warning(
                "Skipping a thread whose FreeBSD NT_PRSTATUS is %d bytes; a %s one is %d",
                len(desc),
                self.arch.name,
                header_size + gregset.size,
            )
            return

        pr_version, pr_statussz, pr_gregsetsz, _, _, pr_cursig, pr_pid = struct.unpack_from(header_fmt, desc)

        if pr_version != 1 or pr_statussz != len(desc) or pr_gregsetsz != gregset.size:
            log.warning(
                "Skipping a thread whose FreeBSD NT_PRSTATUS describes itself as version %d, %d bytes with a "
                "%d byte register set; expected version 1, %d bytes and %d",
                pr_version,
                pr_statussz,
                pr_gregsetsz,
                len(desc),
                gregset.size,
            )
            return

        registers = dict(zip(gregset.names, struct.unpack_from(end + gregset.fmt, desc, header_size), strict=True))
        registers.pop("xxx", None)

        self.__current_thread.update({"pr_cursig": pr_cursig, "pr_pid": pr_pid, "registers": registers})

    def __parse_netbsd_regs(self, desc, gregset):
        """
        Parse out a NetBSD struct reg, accumulating the general purpose register values. NetBSD writes one
        of these per LWP, in a note named "NetBSD-CORE@<lwpid>"; its NT_PRSTATUS is a struct
        netbsd_elfcore_procinfo, which holds no registers at all.

        :param desc:    the descriptor of a PT_GETREGS note in a NetBSD-CORE namespace.
        :param gregset: the layout of this architecture's struct reg.
        """

        if len(desc) != gregset.size:
            log.warning(
                "Skipping a thread whose NetBSD PT_GETREGS note is %d bytes; a %s struct reg is %d",
                len(desc),
                self.arch.name,
                gregset.size,
            )
            return

        end = ">" if self.arch.memory_endness == "Iend_BE" else "<"
        registers = dict(zip(gregset.names, struct.unpack(end + gregset.fmt, desc), strict=True))
        registers.pop("xxx", None)

        self.__current_thread.update({"registers": registers})

    def __parse_prpsinfo(self, desc):
        pr_fname = desc.pr_fname.split(b"\x00", 1)[0]
        try:
            self.pr_fname = pr_fname.decode()
        except UnicodeDecodeError:
            self.pr_fname = repr(pr_fname)

    def __parse_files(self, desc):
        self._page_size = desc.page_size
        self.filename_lookup = [
            (ent.vm_start, ent.vm_end, ent.page_offset * desc.page_size, self._remote_file_mapper(fn.decode()))
            for ent, fn in zip(desc.Elf_Nt_File_Entry, desc.filename)
        ]

    def __parse_x86_tls(self, desc):
        self.__current_thread["segments"] = {}
        for offset in range(0, len(desc), 4 * 4):
            index, base, limit, flags = struct.unpack_from("4I", desc, offset)
            self.__current_thread["segments"][index] = (base, limit, flags)

    def __parse_auxv(self, desc):
        # An entry is an Elf32_auxv_t or an Elf64_auxv_t: two words of the container's width, which is
        # the pointer width rather than the instruction set's. The two agree for every ordinary core
        # and not for an x32 one, whose ELFCLASS32 auxv describes a process whose registers are 64-bit.
        word = self._reader.elfclass // 8
        fmt = (">" if self.arch.memory_endness == "Iend_BE" else "<") + ("Q" if word == 8 else "I")
        for offset in range(0, len(desc), word * 2):
            code = struct.unpack_from(fmt, desc, offset)[0]
            value = struct.unpack_from(fmt, desc, offset + word)[0]
            code_str = auxv_codes.get(code, code)

            if code_str == "AT_RANDOM":
                value = self.__dummy_clemory.load(value, 0x10)
            elif code_str in ("AT_EXECFN", "AT_PLATFORM"):
                pos = value
                value = bytearray()
                while True:
                    byte = self.__dummy_clemory[pos]
                    if byte == 0:
                        break
                    value.append(byte)
                    pos += 1
                value = bytes(value)

            self.auxv[code_str] = value

    def __reload_children(self):
        self.loader.page_size = self._page_size
        self.loader._perform_relocations = False

        # hack: we are using a loader internal method in a non-kosher way which will cause our children to be
        # marked as the main binary if we are also the main binary
        # work around this by setting ourself here:
        if self.loader._main_object is None:
            self.loader._main_object = self

        child_patches = defaultdict(list)
        for vm_start, vm_end, offset, filename in self.filename_lookup:
            try:
                patch_data = self.__dummy_clemory.load(vm_start, vm_end - vm_start)
            except KeyError:
                pass
            else:
                child_patches[filename].append((vm_start, offset, patch_data))

        remaining_segments = list(self.segments)

        for filename, patches in child_patches.items():
            try:
                with open(filename, "rb") as fp:
                    obj = self.loader._load_object_isolated(fp)
            except (FileNotFoundError, PermissionError, CLECompatibilityError) as ex:
                if isinstance(ex, FileNotFoundError):
                    log.warning(
                        "Dependency %s does not exist on the current system; this core may be incomplete.", filename
                    )
                elif isinstance(ex, CLECompatibilityError):
                    log.warning("Could not find a compatible loader for %s; this core may be incomplete.", filename)
                else:
                    log.warning("Could not load %s; this core may be incomplete.", filename)
                if self.loader._main_object is self:
                    self.loader._main_object = None
                self.child_objects.clear()
                return

            # several ways to try to match the NT_FILE entries to the object
            # (not trivial because offsets can be mapped multiple places)
            # (and because there's no clear pattern for how mappings are included or omitted)
            base_addr = None

            # try one: use the delta between each allocation as a signature (works when the text segment is missing)
            if base_addr is None:
                vm_starts = [a for a, _, _ in patches]
                vm_deltas = [b - a for a, b in zip(vm_starts, vm_starts[1:])]
                segment_starts = [seg.vaddr for seg in obj.segments]
                segment_deltas = [b - a for a, b in zip(segment_starts, segment_starts[1:])]

                # funky lil algorithm to find substrings
                for match_idx in range(len(segment_deltas) - len(vm_deltas) + 1):
                    for idx, vm_delta in enumerate(vm_deltas):
                        if vm_delta != segment_deltas[match_idx + idx]:
                            break
                    else:
                        base_addr = vm_starts[0] - AT.from_lva(obj.segments[match_idx].vaddr, obj).to_rva()
                        break

            # try two: if the file is identity-mapped, it's easy (?)
            if base_addr is None:
                base_reccomendations = [a - b for a, b, _ in patches]
                if all(a == base_reccomendations[0] for a in base_reccomendations):
                    base_addr = base_reccomendations[0]

            # try three: if we have the zero offset then it's easy (?)
            if base_addr is None:
                if patches[0][1] == 0:
                    base_addr = patches[0][0]

            if base_addr is None:
                log.warning("Could not load %s (could not determine base); core may be incomplete", filename)
                if self.loader._main_object is self:
                    self.loader._main_object = None
                self.child_objects.clear()
                return

            obj._custom_base_addr = base_addr
            self.child_objects.append(obj)

            # figure out how the core's data should affect the child object's data
            # iterate over all the core segments, since the only time we will need to make a change to the child's
            # memory is if the core has something to say about it
            # if there is ANY OVERLAP AT ALL, copy over the relevant data and nuke the segment
            # then, if there is any part of the segment which DOESN'T correspond to a child segment, inject a new memory
            #  backer into the child for the relevant data

            max_addr = base_addr + (obj.max_addr - obj.min_addr)
            i = 0
            while i < len(remaining_segments):
                seg = remaining_segments[i]
                # check for overlap (overapproximation)
                if base_addr <= seg.vaddr <= max_addr or seg.vaddr <= base_addr < seg.vaddr + seg.memsize:
                    remaining_segments.pop(i)

                    # if there is data before the beginning of the child or after the end,
                    # make new artificial segments for it
                    if seg.vaddr < base_addr:
                        size = base_addr - seg.vaddr
                        remaining_segments.insert(i, Segment(seg.offset, seg.vaddr, size, size))
                        i += 1
                    if seg.max_addr > max_addr:
                        size = seg.max_addr - max_addr
                        offset = seg.memsize - size
                        remaining_segments.insert(i, Segment(seg.offset + offset, seg.vaddr + offset, size, size))
                        i += 1

                    # ohhhh this is SUCH a confusing address space-conversation problem!
                    # we're going to enumerate the contents of the core segment. at each point we find the relevant
                    # child backer. if this skips any content, inject a backer into the child.
                    # then, copy the contents of the core segment that overlaps the child backer.
                    cursor = max(0, base_addr - seg.vaddr)
                    # use filesize and not memsize so we don't overwrite stuff with zeroes if it's omitted from the core
                    while cursor < seg.filesize:
                        child_cursor = cursor + seg.vaddr - base_addr
                        try:
                            child_offset, child_backer = next(obj.memory.backers(child_cursor))
                        except StopIteration:
                            # is this right? is there any behavior we need to account for in the case that there is
                            # somehow no backer past a point mapped by the core?
                            break

                        # have we skipped any part of the core?
                        skip_size = child_offset - child_cursor
                        if skip_size > 0:
                            # inject it into the child
                            obj.memory.add_backer(
                                child_cursor,
                                self.memory.load(AT.from_mva(cursor + seg.vaddr, self).to_rva(), skip_size),
                            )

                        # how much of the child's segment have we skipped by
                        # starting at the beginning of the core segment?
                        child_backer_offset = max(0, -skip_size)
                        # how much of the core's segment have we skipped and handled via injection?
                        core_backer_offset = max(0, skip_size)
                        # how much can we copy?
                        copy_size = min(
                            len(child_backer) - child_backer_offset, seg.memsize - (cursor + core_backer_offset)
                        )
                        if copy_size > 0:
                            # do the copy if we have anything to copy
                            obj.memory.store(
                                child_offset + child_backer_offset,
                                self.memory.load(
                                    AT.from_mva(seg.vaddr + cursor + core_backer_offset, self).to_rva(), copy_size
                                ),
                            )

                        # advance cursor
                        cursor += core_backer_offset + copy_size
                else:
                    i += 1

        # for all remaining segments, make blobs out of them
        mem = self.__dummy_clemory
        for seg in remaining_segments:
            if not seg.memsize:
                continue
            obj = Blob(
                self.binary,
                mem,
                segments=[(seg.vaddr, seg.vaddr, seg.memsize)],
                base_addr=seg.vaddr,
                arch=self.arch,
                entry_point=0,
                force_rebase=True,
            )
            self.child_objects.append(obj)

        self.mapped_base = 0
        self._max_addr = 0
        self.has_memory = False
        if self.loader._main_object is self:
            self.loader._main_object = None
            self.__record_main_object()

    def __record_main_object(self):
        """
        If children objects are reloaded, identify the main object for later use by loader
        """
        for obj in self.child_objects:
            if self.pr_fname and obj.binary_basename.startswith(self.pr_fname):
                self._main_object = obj
                return
            if self._main_filepath is not None and os.path.basename(self._main_filepath) == obj.binary_basename:
                self._main_object = obj
                return

        log.warning("Failed to identify main object in ELFCore")
        self._main_object = self


# ARMEL and ARMHF share a register set.
arm_register_names = (
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "xxx",
    "xxx",
)

# The names of the slots of a Linux elf_gregset_t, in the order the kernel dumps them.
linux_register_names = {
    "AMD64": (
        "r15",
        "r14",
        "r13",
        "r12",
        "rbp",
        "rbx",
        "r11",
        "r10",
        "r9",
        "r8",
        "rax",
        "rcx",
        "rdx",
        "rsi",
        "rdi",
        "xxx",
        "rip",
        "cs",
        "eflags",
        "rsp",
        "ss",
        "fs_base",
        "gs_base",
        "ds",
        "es",
        "xxx",
        "xxx",
    ),
    "X86": (
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "ebp",
        "eax",
        "ds",
        "es",
        "fs",
        "gs",
        "xxx",
        "eip",
        "cs",
        "eflags",
        "esp",
        "ss",
    ),
    "ARMEL": arm_register_names,
    "ARMHF": arm_register_names,
    "AARCH64": (*(f"x{i}" for i in range(32)), "pc", "xxx"),
    "MIPS32": (
        "xxx",
        "xxx",
        "xxx",
        "xxx",
        "xxx",
        "xxx",
        "zero",
        "at",
        "v0",
        "v1",
        "a0",
        "a1",
        "a2",
        "a3",
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
        "t5",
        "t6",
        "t7",
        "s0",
        "s1",
        "s2",
        "s3",
        "s4",
        "s5",
        "s6",
        "s7",
        "t8",
        "t9",
        "k0",
        "k1",
        "gp",
        "sp",
        "s8",
        "ra",
        "lo",
        "hi",
        "pc",
        "bad",
        "sr",
        "status",
        "cause",
    ),
}

# FreeBSD's struct reg, from sys/<machine>/include/reg.h. Segment selectors are dropped on AMD64,
# where the register angr calls "fs" is a segment base rather than a selector.
freebsd_register_sets = {
    "AMD64": RegisterSet(
        "15QIHHIHH5Q",
        (
            "r15",
            "r14",
            "r13",
            "r12",
            "r11",
            "r10",
            "r9",
            "r8",
            "rdi",
            "rsi",
            "rbp",
            "rbx",
            "rdx",
            "rcx",
            "rax",
            "xxx",  # trapno
            "xxx",  # fs
            "xxx",  # gs
            "xxx",  # err
            "es",
            "ds",
            "rip",
            "cs",
            "eflags",
            "rsp",
            "ss",
        ),
    ),
    "X86": RegisterSet(
        "19I",
        (
            "fs",
            "es",
            "ds",
            "edi",
            "esi",
            "ebp",
            "xxx",  # isp
            "ebx",
            "edx",
            "ecx",
            "eax",
            "xxx",  # trapno
            "xxx",  # err
            "eip",
            "cs",
            "eflags",
            "esp",
            "ss",
            "gs",
        ),
    ),
    "AARCH64": RegisterSet(
        "33QII",
        (*(f"x{i}" for i in range(30)), "x30", "sp", "pc", "xxx", "xxx"),  # lr, sp, elr, spsr, padding
    ),
}

# NetBSD's struct reg, from sys/arch/<machine>/include/reg.h, paired with the type NetBSD gives the
# note that carries it: the number of the PT_GETREGS ptrace request, which is PT_FIRSTMACH plus an
# offset that is not the same on every architecture.
netbsd_register_sets = {
    "AMD64": NetBSDRegisters(
        33,
        RegisterSet(
            "26Q",
            (
                "rdi",
                "rsi",
                "rdx",
                "rcx",
                "r8",
                "r9",
                "r10",
                "r11",
                "r12",
                "r13",
                "r14",
                "r15",
                "rbp",
                "rbx",
                "rax",
                "xxx",  # gs
                "xxx",  # fs
                "es",
                "ds",
                "xxx",  # trapno
                "xxx",  # err
                "rip",
                "cs",
                "eflags",
                "rsp",
                "ss",
            ),
        ),
    ),
    "X86": NetBSDRegisters(
        33,
        RegisterSet(
            "16I",
            (
                "eax",
                "ecx",
                "edx",
                "ebx",
                "esp",
                "ebp",
                "esi",
                "edi",
                "eip",
                "eflags",
                "cs",
                "ss",
                "ds",
                "es",
                "fs",
                "gs",
            ),
        ),
    ),
    "AARCH64": NetBSDRegisters(
        32,
        RegisterSet(
            "35Q",
            (*(f"x{i}" for i in range(31)), "sp", "pc", "xxx", "xxx"),  # spsr, tpidr
        ),
    ),
}

auxv_codes = {
    0x0: "AT_NULL",
    0x1: "AT_IGNORE",
    0x2: "AT_EXECFD",
    0x3: "AT_PHDR",
    0x4: "AT_PHENT",
    0x5: "AT_PHNUM",
    0x6: "AT_PAGESZ",
    0x7: "AT_BASE",
    0x8: "AT_FLAGS",
    0x9: "AT_ENTRY",
    0xA: "AT_NOTELF",
    0xB: "AT_UID",
    0xC: "AT_EUID",
    0xD: "AT_GID",
    0xE: "AT_EGID",
    0x11: "AT_CLKTCK",
    0xF: "AT_PLATFORM",
    0x10: "AT_HWCAP",
    0x12: "AT_FPUCW",
    0x13: "AT_DCACHEBSIZE",
    0x14: "AT_ICACHEBSIZE",
    0x15: "AT_UCACHEBSIZE",
    0x16: "AT_IGNOREPPC",
    0x17: "AT_SECURE",
    0x18: "AT_BASE_PLATFORM",
    0x19: "AT_RANDOM",
    0x1A: "AT_HWCAP2",
    0x1F: "AT_EXECFN",
    0x20: "AT_SYSINFO",
    0x21: "AT_SYSINFO_EHDR",
    0x22: "AT_L1I_CACHESHAPE",
    0x23: "AT_L1D_CACHESHAPE",
    0x24: "AT_L2_CACHESHAPE",
    0x25: "AT_L3_CACHESHAPE",
    0x28: "AT_L1I_CACHESIZE",
    0x29: "AT_L1I_CACHEGEOMETRY",
    0x2A: "AT_L1D_CACHESIZE",
    0x2B: "AT_L1D_CACHEGEOMETRY",
    0x2C: "AT_L2_CACHESIZE",
    0x2D: "AT_L2_CACHEGEOMETRY",
    0x2E: "AT_L3_CACHESIZE",
    0x2F: "AT_L3_CACHEGEOMETRY",
}

register_backend("elfcore", ELFCore)
