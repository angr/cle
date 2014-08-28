import logging
import idalink
from .archinfo import ArchInfo
import os
import pdb
import struct

l = logging.getLogger("cle.idabin")

class IdaBin(object):
    """ Get informations from binaries using IDA.
    This replaces the old Binary class and integrates it into CLE as a fallback
    """
    def __init__(self, binary, base_addr = None):

        self.rebase_addr = None
        self.binary = binary
        archinfo = ArchInfo(binary)
        self.archinfo = archinfo
        arch_name = archinfo.name
        processor_type = archinfo.ida_arch
        if(archinfo.bits == 32):
            ida_prog = "idal"
        else:
            ida_prog = "idal64"

        self.arch = archinfo.to_qemu_arch(arch_name)
        self.simarch = archinfo.to_simuvex_arch(arch_name)

        #pull = base_addr is None
        pull = False
        l.debug("Loading binary %s using IDA with arch %s" % (binary, processor_type))
        self.ida = idalink.IDALink(binary, ida_prog=ida_prog,
                                   processor_type=processor_type, pull = pull)

        self.badaddr = self.ida.idc.BADADDR
        self.memory = self.ida.mem
        if base_addr is not None:
            self.rebase(base_addr)
        else:
            self.rebase_addr = 0

        self.imports = self.__get_imports()

        self.exports = self.__get_exports()
        self.custom_entry_point = None # Not implemented yet
        self.entry_point = self.__get_entry_point()

    def rebase(self, base_addr):
        """ Rebase the binary at address @base_addr """
        l.debug("-> Rebasing %s to address 0x%x (IDA)" %
                (os.path.basename(self.binary), base_addr))
        if self.get_min_addr() >= base_addr:
            l.debug("It looks like the current idb is already rebased!")
        else:
            if self.ida.idaapi.rebase_program(
                base_addr, self.ida.idaapi.MSF_FIXONCE |
                self.ida.idaapi.MSF_LDKEEP) != 0:
                raise Exception("Rebasing of %s failed!", self.binary)
            self.ida.remake_mem()
            self.rebase_addr = base_addr
            #self.__rebase_exports(base_addr)

            # We also need to update the exports' addresses
            self.exports = self.__get_exports()

    def in_which_segment(self, addr):
        """ Return the segment name at address @addr (IDA)"""
        seg = self.ida.idc.SegName(addr)
        if len(seg) == 0:
            seg = "unknown"
        return seg

    def __find_got(self):
        """ Locate the section (e.g., .got) that should be updated when
        relocating functions (that's where we want to write absolute addresses).
        """
        sec_name = self.archinfo.got_section_name()
        self.got_begin = None
        self.got_end = None

        for seg in self.ida.idautils.Segments():
            name = self.ida.idc.SegName(seg)
            if name == sec_name:
                self.got_begin = self.ida.idc.SegStart(seg)
                self.got_end = self.ida.idc.SegEnd(seg)

        # If we reach this point, we should have the addresses
        if self.got_begin is None or self.got_end is None:
            raise Exception("This architecture has no section %s :(", sec_name)

    def __in_proper_section(self, addr):
        """ Is @addr in the proper section for this architecture ?"""
        return (addr > self.got_begin and addr < self.got_end)

    def function_name(self, addr):
        """ Return the function name at address @addr (IDA) """
        name = self.ida.idc.GetFunctionName(addr)
        if len(name) == 0:
            name = "UNKNOWN"
        return name

    def __lookup_symbols(self, symbols):
        """ Resolves a bunch of symbols denoted by the list @symbols
            Returns: a dict of the form {symb:addr}"""
        addrs = {}

        for sym in symbols:
            addr = self.get_symbol_addr(sym)
            if not addr:
                l.debug("Symbol %s was not found (IDA)" % sym)
                continue
            addrs[sym] = addr
        return addrs

    def get_symbol_addr(self, sym):
        """ Get the address of the symbol @sym from IDA
            Returns: an address
        """
        #addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
        addr = self.ida.idc.LocByName(sym)
        if addr == self.ida.idc.BADADDR:
            addr = None

    def __get_exports(self):
        """ Get binary's exports names from IDA and return a list"""
        exports = {}
        for item in list(self.ida.idautils.Entries()):
            name = item[-1]
            if name is None:
                continue
            ea = item[1]
            exports[name] = ea
            #l.debug("\t export %s 0x@%x" % (name, ea))
        return exports

    def __get_ida_imports(self):
        """ Extract imports from binary (IDA)"""
        import_modules_count = self.ida.idaapi.get_import_module_qty()
        self.raw_imports = {}

        for i in xrange(0, import_modules_count):
            self.current_module_name = self.ida.idaapi.get_import_module_name(
                i)
            self.ida.idaapi.enum_import_names(i, self.__import_entry_callback)

    def __import_entry_callback(self, ea, name, entry_ord):
        """ Callback function for IDA's enum_import_names"""
        self.raw_imports[name] = ea
        return True

    def __get_imports(self):
        """ Extract imports from the binary. This uses the exports we get from IDA,
        and then tries to find the GOT entries related to them.
        It returns a dict {import:got_address}
        """
        # Locate the GOT on this architecture
        self.__find_got()

        # Get the list of imports from IDA
        self.__get_ida_imports()

        # Then process it to get the correct addresses
        imports = {}
        for name, ea in self.raw_imports.iteritems():
            # If this architecture uses the plt directly, then we need to look
            # in the code segment.
            if self.archinfo.got_section_name() == '.plt':
                lst = list(self.ida.idautils.CodeRefsTo(ea, 1))
            else:
                lst = list(self.ida.idautils.DataRefsTo(ea))

            for addr in lst:
                if self.__in_proper_section(addr) and addr != self.badaddr:
                    imports[name] = addr
                    l.debug("\t -> has import %s - GOT entry @ 0x%x" % (name, addr))
        return imports

    def get_min_addr(self):
        """ Get the min address of the binary (IDA)"""
        nm = self.ida.idc.NextAddr(0)
        pm = self.ida.idc.PrevAddr(nm)

        if pm == self.ida.idc.BADADDR:
            return nm
        else:
            return pm

    def get_max_addr(self):
        """ Get the max address of the binary (IDA)"""
        pm = self.ida.idc.PrevAddr(self.ida.idc.MAXADDR)
        nm = self.ida.idc.NextAddr(pm)

        if nm == self.ida.idc.BADADDR:
            return pm
        else:
            return nm

    def __get_entry_point(self):
        """ Get the entry point of the binary (from IDA)"""
        if self.custom_entry_point is not None:
            return self.custom_entry_point
        return self.ida.idc.BeginEA()

    def resolve_import_dirty(self, sym, new_val):
        """ Resolve import for symbol @sym the dirty way, i.e. find all
        references to it in the code and replace it with the address @new_val
        inline (instead of updating GOT slots)
        Don't use this unless you really have to, use resolve_import_with instead.
        """

        #l.debug("\t %s resolves to 0x%x", sym, new_val)

        # Try IDA's _ptr
        plt_addr = self.get_symbol_addr(sym + "_ptr")
        if (plt_addr):
            addr = [plt_addr]
            return self.update_addrs(addr, new_val)

        # Try the __imp_name
        plt_addr = self.get_symbol_addr("__imp_" + sym)
        if (plt_addr):
            addr = list(self.ida.idautils.DataRefsTo(plt_addr))
            return self.update_addrs(addr, new_val)

        # Try the normal name
        plt_addr = self.get_symbol_addr(sym)
        if (plt_addr):
            addr = list(self.ida.idautils.DataRefsTo(plt_addr))
            # If not datarefs, try coderefs. It can happen on PPC
            if len(addr) == 0:
                addr = list(self.ida.idautils.CodeRefsTo(plt_addr))
            return self.update_addrs(addr, new_val)

        # If none of them has an address, that's a problem
            l.debug("Warning: could not find references to symbol %s (IDA)" % sym)

    def resolve_import_with(self, name, newaddr):
        """ Resolve import @name with address @newaddr, that is, update the GOT
            entry for @name with @newaddr
            Note: this should be called update_got_slot to match the Elf class.
        """
        if name in self.imports:
            addr = self.imports[name]
            self.update_addrs([addr], newaddr)

    def update_addrs(self, update_addrs, new_val):
        """ Updates all the addresses of @update_addrs with @new_val
            @updatre_addrs is a list
            @new_val is an address
        """
        arch = self.archinfo.get_simuvex_obj()
        fmt = arch.struct_fmt
        packed = struct.pack(fmt, new_val)

        for addr in update_addrs:
            #l.debug("... setting 0x%x to 0x%x", addr, new_val)
            for n, p in enumerate(packed):
                self.ida.mem[addr + n] = p

    def is_thumb(self, addr):
        """ Is the address @addr in thumb mode ? (ARM) """
        if "arm" in self.arch:
            return self.binary_by_addr(addr).ida.idc.GetReg(addr, "T") == 1
