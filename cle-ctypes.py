#!/usr/bin/env python

from ctypes import *
import os
import logging

l = logging.getLogger("cle")

class CLException(Exception):
    def __init__(self, val):
        self.val = val

    def __str__(self):
        return repr(self.val)


class Segment(object):
    """ Simple representation of an ELF file segment"""
    def __init__(self, name, vaddr, size, offset=None):
        self.vaddr = vaddr
        self.size = size
        self.offset = offset
        self.name = name

    def contains_addr(self, addr):
            return ((addr > self.vaddr) and (addr < self.vaddr + self.size))


class Elf(object):
    """ Representation of loaded Elf binaries """
    def __init__(self, binary):

        #Interface to libcle
        self.lib = cdll.LoadLibrary("./libcle_ctypes.so")
        self.lib.get_arch.restype = c_char_p

        self.segments = [] # List of segments
        self.memory = {} # Private virtual address space, without relocations
        self.symbols = {} # Object's symbols
        self.binary = binary
        self.load(binary)
        self.base_addr = self.lib.get_base_addr()

#    def __del__(self):
#        self.lib.__cleanup()


    def load(self, binary):
        """ Load the binary file @binary into memory"""

        load_file = getattr(self.lib, "__load_file")
        ret =load_file(binary)
        if (ret != 0):
            print "\tCould not load %s, error %d from libcle (see errno.h)" % (binary, ret)
            return
            #raise CLException("Error loading the binary")

        print "\n--- CLE::Loading binary file %s --- " % binary

        self.entry_point = self.lib.get_entry_point()
        print "\t--> Entry point @0x%x" % self.entry_point
        self.__load_text()
        self.__load_data()


    def contains_addr(self, addr):
        """ Is @vaddr in one of the segment we have loaded ?
        (i.e., is it mapped into memory ?)
        """
        for i in self.segments:
            if contains_addr(i, addr):
                return True
        return False


    def in_which_segment(self, vaddr):
        """ What is the segment name containing @vaddr ?"""
        for s in self.segments:
            if s.contains_addr(vaddr):
                return s.name
        return None


    def load_segment(self, offset, size, vaddr, name=None):
        """ Load a segment into memory """

        try:
            f = open(self.binary, 'r')
            f.seek(offset)
        except IOError:
            print("\tFile does not exist", self.binary)

        # Fill the memory dict with addr:value
        for i in range(vaddr, vaddr + size):
            # Is something else already loaded at this address ?
            if self.memory.has_key(i):
                raise CLException("WTF?? @0x%x Segments overlaping in memory", i)
            self.memory[i] = f.read(1)

        # Add the segment to the list of loaded segments
        seg = Segment(name, vaddr, size)
        self.segments.append(seg)
        print "\t--> Loaded segment %s @0x%x with size:0x%x" % (name, vaddr, size)


    def get_arch(self):
        """ Stub to libcle: gets the processor architecture of the binary """
        return self.lib.get_arch()


    def find_string_table(self):
        """ Stub to licle"""
        return self.lib.get_strtab_vaddr()


    def get_string_table_sz(self):
        """ Stub to libcle"""
        return self.lib.get_strtab_sz()


    def get_lib_names(self):
        """ What are the dependencies of the @self.binary ?
        This gets the names of the libraries we should load as well
        """

        so_off = self.__get_lib_names_offsets()
        string_table = self.find_string_table()
        sz = self.get_string_table_sz()

        print "\tString table is in segment %s" % self.in_which_segment(string_table)

        # We expect the string table to be in the text or data segment, thus
        # already loaded
        if ((self.in_which_segment(string_table)) == None):
            raise CLException("String table is not loaded")

        names = []
        for off in so_off:
            name = ""
            for addr in range(string_table + off, string_table + sz):
                try:
                    name += self.memory[addr]
                    if (self.memory[addr] == '\0'):
                        names.append(name[0:-1]) # Strip the '\0' char
                        break
                except KeyError:
                    print("\tAddress does not exist (nothing loaded here)", hex(addr))
        return names


    def __get_lib_names_offsets(self):
        """
        Returns the dependencies of @self.binary in the form of
        offsets from the beginning of the string table.
        You probably want to use get_lib_names directly.
        """
        self.lib.get_lib_names_offsets.restype = POINTER(c_int)
        needed = self.lib.get_lib_names_offsets()
        sz = self.lib.get_num_libs()
        so_off = []
        if (needed):
            for i in needed[0:sz]:
                so_off.append(i)
        return so_off


    def __load_text(self):
        """ Stub to load the text segment """
        text_offset = self.lib.get_text_offset()
        text_size = self.lib.get_text_filesz()
        text_vaddr = self.lib.get_text_vaddr()
        self.load_segment(text_offset, text_size, text_vaddr, "text")


    def __load_data(self):
        """ Stub to load the data segment """
        # offset of .data in binaryfile
        data_offset = self.lib.get_data_offset()
        data_size = self.lib.get_data_filesz()
        data_vaddr = self.lib.get_data_vaddr()
        self.load_segment(data_offset, data_size, data_vaddr, "data")



class CLE(object):
    """ CLE ELF loader
    This class makes use of libcle_ctypes to access low level ELF information.
    See libcle and libcle_ctypes for more info.
    """

    def __init__(self, binary):
        """ @path is the path to licle_ctypes.so"""

        self.memory = {} # Dictionary representation of the memory
        self.shared_objects =[] # Executables and libraries
        self.path = binary
        self.exe = Elf(binary)


    def load_shared_libs(self):
        shared_libs = self.exe.get_lib_names()
        for path in shared_libs:
            if path: self.__load_so(path)


    def __load_so(self, soname):
        path = self.__search_so(soname)
        if (path == None):
            print "\tCould not find shared object %s" % repr(soname)
            return
        else:
            so = Elf(path)
            self.shared_objects.append(so)


    def __search_so(self, soname):
        loc = []
        loc.append(os.getenv("LD_LIBRARY_PATH"))
        loc.append(os.path.dirname(self.path))

        for ld_path in loc:
            if not ld_path: continue
            for s_path, s_dir, s_file in os.walk(ld_path):
                sopath = os.path.join(s_path,soname)
                if os.path.exists(sopath):
                    print "\t-->Found %s" % sopath
                    return sopath
        return None


cle = CLE("../telstra/httpd")
cle.load_shared_libs()
