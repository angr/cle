import logging
import idalink
from .archinfo import ArchInfo
import os
import pdb

l = logging.getLogger("cle.idabin")

class IdaBin(object):
    """ Get informations from binaries using IDA. This replaces the old Binary
    class and integrates it into CLE as a fallback """
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

        self.memory = self.ida.mem
        if base_addr is not None:
            self.rebase(base_addr)

        self.imports = {}
        self.__get_imports()

        self.exports = self.__get_exports()
        self.custom_entry_point = None # Not implemented yet
        self.entry_point = self.__get_entry_point()

    def rebase(self, base_addr):
        """ Rebase binary at address @base_addr """
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

            # We also need to update the exports' addresses
            #self.exports = self.__get_exports()

    def in_which_segment(self, addr):
        """ Return the segment name at address @addr (IDA)"""
        seg = self.ida.idc.SegName(addr)
        if len(seg) == 0:
            seg = "unknown"
        return seg

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
            addr = self.__get_symbol_addr(sym)
            if not addr:
                l.debug("Symbol %s was not found (IDA)" % sym)
                continue
            addrs[sym] = addr

    def __get_symbol_addr(self, sym):
        """ Get the address of the symbol @sym from IDA
            Returns: an address
        """
        addr = self.ida.idaapi.get_name_ea(self.ida.idc.BADADDR, sym)
        if addr == self.ida.idc.BADADDR:
            addr = None

    def __get_exports(self):
        """ Get binary's exports names from IDA and return a list"""
        exports = {}
        for item in list(self.ida.idautils.Entries()):
            name = item[3]
            ea = item[2]
            exports[name] = ea
            # i = {}
            # i["index"] = item[0]
            # i["ordinal"] = item[1]
            # i["ea"] = item[2]
            # i["name"] = item[3]
            #exports.append(i)
        return exports

    def __get_imports(self):
        """ Extract imports from binary (IDA)"""
        import_modules_count = self.ida.idaapi.get_import_module_qty()

        for i in xrange(0, import_modules_count):
            self.current_module_name = self.ida.idaapi.get_import_module_name(
                i)
            self.ida.idaapi.enum_import_names(i, self.__import_entry_callback)

    def __import_entry_callback(self, ea, name, entry_ord):
        self.imports[name] = ea
        return True

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
        inline (instead of updating GOT slots)"""

        #l.debug("\t %s resolves to 0x%x", sym, new_val)

        # Try IDA's _ptr
        plt_addr = self.__get_symbol_addr(sym + "_ptr")
        if (plt_addr):
            addr = [plt_addr]
            return self.__update_addrs(addr, newval)

        # Try the __imp_name
        plt_addr = self.__get_symbol_addr("__imp_" + sym)
        if (plt_addr):
            addr = list(self.ida.idautils.DataRefsTo(plt_addr))
            return self.__update_addrs(addr, newval)

        # Try the normal name
        plt_addr = self.__get_symbol_addr(sym)
        if (plt_addr):
            addr = list(self.ida.idautils.DataRefsTo(plt_addr))
            # If not datarefs, try coderefs. It can happen on PPC
            if len(addr) == 0:
                addr = list(self.ida.idautils.CodeRefsTo(plt_addr))
            return self.__update_addrs(addr, newval)

        # If none of them has an address, that's a problem
            l.debug("Warning: could not find references to symbol %s (IDA)" % sym)

    def __update_addrs(update_addrs, newval):
        fmt = self.arch.struct_fmt
        packed = struct.pack(fmt, new_val)

        for addr in update_addrs:
            l.debug("... setting 0x%x to 0x%x", addr, new_val)
            for n, p in enumerate(packed):
                self.ida.mem[addr + n] = p


