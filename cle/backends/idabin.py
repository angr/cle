import os
import logging
import binascii

from . import Backend, register_backend
from ..errors import CLEError, CLEFileNotFoundError

l = logging.getLogger("cle.idabin")

try:
    idalink = __import__('idalink').idalink
except ImportError:
    idalink = None


class IDABin(Backend):
    """
    Get information from binaries using IDA.
    """
    is_default = True # Tell CLE to automatically consider using the IDABin backend

    def __init__(self, binary, *args, **kwargs):
        if idalink is None:
            raise CLEError("Install the idalink module to use the IDABin backend!")

        super(IDABin, self).__init__(binary, *args, **kwargs)

        if self.binary is None:
            raise CLEError("You can't use a file stream with the ida backend, for what I hope are obvious reasons")
        if self.arch is None:
            raise CLEError("You must specify a arch in order to use the IDABin backend")

        ida_prog = "idal64" # We don't really need 32 bit idal, do we ?
        processor_type = self.arch.ida_processor

        l.debug("Loading binary %s using IDA with arch %s", self.binary, processor_type)

        self.ida_path = self._make_tmp_copy(self.binary)
        try:
            self.ida = idalink(self.ida_path, ida_prog=ida_prog,
                                       processor_type=processor_type).link
        except idalink.IDALinkError as e:
            raise CLEError("IDALink returned error: %s" % e)

        self.BADADDR = self.ida.idc.BADADDR
        l.info('Loading memory from ida, this will take a minute...')
        memcache = self.ida.memory

        for segaddr in self.ida.idautils.Segments():
            segend = self.ida.idc.SegEnd(segaddr)
            string = ''.join(memcache[i] if i in memcache else '\0' for i in xrange(segaddr, segend))
            self.memory.add_backer(segaddr, string)

        self.got_begin = None
        self.got_end = None
        self.raw_imports = {}
        self.current_module_name = None

        self.imports = self._get_imports()
        self.resolved_imports = {}
        self.linking = self._get_linking_type()

        self.exports = self._get_exports()

        l.warning('The IDABin module is not well supported. Good luck!')

    @staticmethod
    def _make_tmp_copy(path, suffix=None):
        """
        Makes a copy of obj into CLE's tmp directory.
        """
        if not os.path.exists('/tmp/cle'):
            os.mkdir('/tmp/cle')

        if hasattr(path, 'seek') and hasattr(path, 'read'):
            stream = path
        else:
            try:
                stream = open(path, 'rb')
            except IOError:
                raise CLEFileNotFoundError("File %s does not exist :(. Please check that the"
                                           " path is correct" % path)
        bn = binascii.hexlify(os.urandom(5))
        if suffix is not None:
            bn += suffix
        dest = os.path.join('/tmp/cle', bn)
        l.info("\t -> copy obj %s to %s", path, dest)

        with open(dest, 'wb') as dest_stream:
            while True:
                dat = stream.read(1024 * 1024)
                if len(dat) == 0:
                    break
                dest_stream.write(dat)

        return dest

    @staticmethod
    def is_compatible(stream):
        return stream == 0  # Don't use this for anything unless it's manually selected

    def in_which_segment(self, addr):
        """
        Return the segment name at address `addr` (IDA).
        """
        seg = self.ida.idc.SegName(addr)
        if len(seg) == 0:
            seg = "unknown"
        return seg

    def _find_got(self):
        """
        Locate the section (e.g. .got) that should be updated when relocating functions (that's where we want to
        write absolute addresses).
        """
        sec_name = self.arch.got_section_name
        self.got_begin = None
        self.got_end = None

        for seg in self.ida.idautils.Segments():
            name = self.ida.idc.SegName(seg)
            if name == sec_name:
                self.got_begin = self.ida.idc.SegStart(seg)
                self.got_end = self.ida.idc.SegEnd(seg)

        # If we reach this point, we should have the addresses
        if self.got_begin is None or self.got_end is None:
            l.warning("No section %s, is this a static binary ? (or stripped)", sec_name)
            return False
        return True

    def _in_proper_section(self, addr):
        """
        Is `addr` in the proper section for this architecture ?
        """
        return self.got_begin < addr < self.got_end

    def function_name(self, addr):
        """
        Return the function name at address `addr` (IDA).
        """
        name = self.ida.idc.GetFunctionName(addr)
        if len(name) == 0:
            name = "UNKNOWN"
        return name

    def _lookup_symbols(self, symbols):
        """
        Resolves a bunch of symbols denoted by the list `symbols`.

        :returns: A dict of the form {symb:addr}.
        """
        addrs = {}

        for sym in symbols:
            addr = self.get_symbol_addr(sym)
            if not addr:
                l.debug("Symbol %s was not found (IDA)", sym)
                continue
            addrs[sym] = addr
        return addrs

    def get_symbol_addr(self, sym):
        """
        Get the address of the symbol `sym` from IDA.

        :returns: An address.
        """
        #addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
        addr = self.ida.idc.LocByName(sym)
        if addr == self.BADADDR:
            addr = None
        return addr

    def _get_exports(self):
        """
        Get the binary exports names from IDA and return a list.
        """
        exports = {}
        for item in list(self.ida.idautils.Entries()):
            name = item[-1]
            if name is None:
                continue
            ea = item[1]
            exports[name] = ea
            #l.debug("\t export %s 0x@%x" % (name, ea))
        return exports

    def _get_ida_imports(self):
        """
        Extract imports from binary (IDA).
        """
        l.warning("TODO: improve this: IDA mixes functions and global data in exports, this will cause issues.")
        import_modules_count = self.ida.idaapi.get_import_module_qty()
        self.raw_imports = {}

        for i in xrange(0, import_modules_count):
            self.current_module_name = self.ida.idaapi.get_import_module_name(i)
            self.ida.idaapi.enum_import_names(i, self._import_entry_callback)

    def _import_entry_callback(self, ea, name, entry_ord): # pylint: disable=unused-argument
        """
        Callback function for IDA's enum_import_names.
        """
        self.raw_imports[name] = ea
        return True

    def _get_imports(self):
        """
        Extract imports from the binary. This uses the exports we get from IDA and then tries to find the GOT
        entries related to them.

        :returns:   a dict of the form {import:got_address}.
        """
        # Get the list of imports from IDA
        self._get_ida_imports()

        # Static binary
        if len(self.raw_imports) == 0:
            l.info("This is a static binary.")
            return

        # Locate the GOT on this architecture. If we can't, let's just default
        # to IDA's imports (which gives stub addresses instead).
        if not self._find_got():
            l.warning("We could not identify the GOT section. This looks like a stripped binary. IDA'll probably give "
                      "us PLT stubs instead, so keep in mind that Ld.find_symbol_got_entry() and friends won't work "
                      "with actual GOT addresses. If that's a problem, use the ELF backend instead.")
            return self.raw_imports

        # Then process it to get the correct addresses
        imports = {}
        for name, ea in self.raw_imports.iteritems():
            # If this architecture uses the plt directly, then we need to look
            # in the code segment.
            if self.arch.got_section_name == '.plt':
                lst = list(self.ida.idautils.CodeRefsTo(ea, 1))
            else:
                lst = list(self.ida.idautils.DataRefsTo(ea))

            for addr in lst:
                if self._in_proper_section(addr) and addr != self.BADADDR:
                    imports[name] = addr
                    l.debug("\t -> has import %s - GOT entry @ 0x%x", name, addr)
        return imports

    @property
    def min_addr(self):
        """
        Get the min address of the binary (IDA).
        """
        nm = self.ida.idc.NextAddr(0)
        pm = self.ida.idc.PrevAddr(nm)

        if pm == self.BADADDR:
            return nm
        else:
            return pm

    @property
    def max_addr(self):
        """
        Get the max address of the binary (IDA).
        """
        pm = self.ida.idc.PrevAddr(self.ida.idc.MAXADDR)
        nm = self.ida.idc.NextAddr(pm)

        if nm == self.BADADDR:
            return pm
        else:
            return nm

    @property
    def entry(self):
        if self._custom_entry_point is not None:
            return self._custom_entry_point + self.mapped_base
        return self.ida.idc.BeginEA() + self.mapped_base

    def resolve_import_dirty(self, sym, new_val):
        """
        Resolve import for symbol `sym` the dirty way, i.e. find all references to it in the code and replace it with
        the address `new_val` inline (instead of updating GOT slots). Don't use this unless you really have to, use
        :func:`resolve_import_with` instead.
        """

        #l.debug("\t %s resolves to 0x%x", sym, new_val)

        # Try IDA's _ptr
        plt_addr = self.get_symbol_addr(sym + "_ptr")
        if plt_addr:
            self.memory.pack_word(plt_addr, new_val)
            return

        # Try the __imp_name
        plt_addr = self.get_symbol_addr("__imp_" + sym)
        if plt_addr:
            for addr in self.ida.idautils.DataRefsTo(plt_addr):
                self.memory.pack_word(addr, new_val)
            return

        # Try the normal name
        plt_addr = self.get_symbol_addr(sym)
        if plt_addr:
            addrlist = list(self.ida.idautils.DataRefsTo(plt_addr))
            # If not datarefs, try coderefs. It can happen on PPC
            if len(addrlist) == 0:
                addrlist = list(self.ida.idautils.CodeRefsTo(plt_addr))
            for addr in addrlist:
                self.memory.pack_word(addr, new_val)
            return

        # If none of them has an address, that's a problem
        l.warning("Could not find references to symbol %s (IDA)", sym)

    def set_got_entry(self, name, newaddr):
        """
        Resolve import `name` with address `newaddr`. That is, update the GOT entry for `name` with `newaddr`.
        """
        if name not in self.imports:
            l.warning("%s not in imports", name)
            return

        addr = self.imports[name]
        self.memory.pack_word(addr, newaddr)

    def is_thumb(self, addr):
        """
        Is the address `addr` in thumb mode ? (ARM).
        """
        if not "arm" in self.arch:
            return False
        return self.ida.idc.GetReg(addr, "T") == 1

    def get_strings(self):
        """
        Extract strings from binary (IDA).

        :returns:   An array of strings.
        """
        ss = self.ida.idautils.Strings()
        string_list = []
        for s in ss:
            t_entry = (s.ea, str(s), s.length)
            string_list.append(t_entry)
        return string_list

    def _get_linking_type(self):
        """
        Returns whether a binary is statically or dynamically linked based on its imports.
        """
        # TODO: this is not the best, and with the Elf class we actually look for the presence of a dynamic table. We
        # should do it with IDA too.

        if len(self.raw_imports) == 0:
            return "static"
        else:
            return "dynamic"

    # must be able to duck type as a MetaELF subclass

    @property
    def plt(self):
        # I know there's a way to do this but BOY do I not want to do it right now
        return {}

    @property
    def reverse_plt(self):
        return {}

    @staticmethod
    def get_call_stub_addr(name): # pylint: disable=unused-argument
        return None

    @property
    def is_ppc64_abiv1(self):
        # IDA 6.9 segfaults when loading ppc64 abiv1 binaries so....
        return False

register_backend("idabin", IDABin)
