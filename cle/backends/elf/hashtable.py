from __future__ import annotations

import struct


class ELFHashTable:
    """
    Functions to do lookup from a HASH section of an ELF file.

    Information: http://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-48031.html
    """

    def __init__(self, symtab, stream, offset):
        """
        :param symtab:  The symbol table to perform lookups from (as a pyelftools SymbolTableSection).
        :param stream:  A file-like object to read from the ELF's memory.
        :param offset:  The offset in the object where the table starts.
        """
        self.symtab = symtab
        fmt = "<" if symtab.structs.little_endian else ">"
        stream.seek(offset)
        self.nbuckets, self.nchains = struct.unpack(fmt + "II", stream.read(8))
        self.buckets = struct.unpack(fmt + "I" * self.nbuckets, stream.read(4 * self.nbuckets))
        self.chains = struct.unpack(fmt + "I" * self.nchains, stream.read(4 * self.nchains))

    def get(self, k):
        """
        Perform a lookup. Returns a pyelftools Symbol object, or None if there is no match.

        :param k:   The string to look up.
        """
        if self.nbuckets == 0:
            return None, None
        num_symbols = self.symtab.num_symbols()
        symndx = self.buckets[self.elf_hash(k) % self.nbuckets]
        # Both the bucket and every chain entry are indices the file chose. They can point past
        # the symbol table, past the chain array, or back at an index already visited, so the walk
        # is bounded by the chain array it walks: that is enough steps to reach every index the
        # chain can reach, and a cycle runs out instead of spinning.
        for _ in range(self.nchains):
            if symndx == 0 or symndx >= num_symbols or symndx >= self.nchains:
                return None, None
            sym = self.symtab.get_symbol(symndx)
            if sym.name == k:
                return symndx, sym
            symndx = self.chains[symndx]
        return None, None

    # from http://www.partow.net/programming/hashfunctions/
    @staticmethod
    def elf_hash(key):
        h = 0
        x = 0
        for c in key:
            h = (h << 4) + ord(c)
            x = h & 0xF0000000
            if x != 0:
                h ^= x >> 24
            h &= ~x
        return h


class GNUHashTable:
    """
    Functions to do lookup from a GNU_HASH section of an ELF file.

    Information: https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections
    """

    def __init__(self, symtab, stream, offset):
        """
        :param symtab:       The symbol table to perform lookups from (as a pyelftools SymbolTableSection).
        :param stream:       A file-like object to read from the ELF's memory.
        :param offset:       The offset in the object where the table starts.
        """
        self.symtab = symtab
        # Every word in this table is laid out by the container: the bloom words are one ELF class
        # wide, four bytes in an ELFCLASS32 file and eight in an ELFCLASS64 one, and the byte order
        # is the file's. What the architecture says is a different question.
        self.fmt = "<" if symtab.structs.little_endian else ">"
        self.c = symtab.structs.elfclass
        fmtsz = "I" if self.c == 32 else "Q"

        stream.seek(offset)
        data = stream.read(16)
        self.nbuckets, self.symndx, self.maskwords, self.shift2 = struct.unpack(self.fmt + "IIII", data)

        self.bloom = struct.unpack(self.fmt + fmtsz * self.maskwords, stream.read(self.c * self.maskwords // 8))
        self.buckets = struct.unpack(self.fmt + "I" * self.nbuckets, stream.read(4 * self.nbuckets))
        self.hash_ptr = stream.tell()
        self.stream = stream

    def _matches_bloom(self, H1):
        C = self.c
        H2 = H1 >> self.shift2
        N = (H1 // C) & (self.maskwords - 1)
        BITMASK = (1 << (H1 % C)) | (1 << (H2 % C))
        return (self.bloom[N] & BITMASK) == BITMASK if N < len(self.bloom) else False

    def get(self, k):
        """
        Perform a lookup. Returns a pyelftools Symbol object, or None if there is no match.

        :param k:        The string to look up
        """
        h = self.gnu_hash(k)
        if not self._matches_bloom(h):
            return None, None
        n = self.buckets[h % self.nbuckets]
        if n == 0:
            return None, None
        num_symbols = self.symtab.num_symbols()
        # The bucket is an index the file chose, and the walk from it runs until a chain word says
        # to stop, so both are bounded by the symbol table they index.
        while n < num_symbols:
            sym = self.symtab.get_symbol(n)
            if sym.name == k:
                return n, sym
            self.stream.seek(self.hash_ptr + 4 * (n - self.symndx))
            word = self.stream.read(4)
            # The low bit of the chain word, as the file wrote it, ends the chain.
            if len(word) < 4 or struct.unpack(self.fmt + "I", word)[0] & 1 == 1:
                break
            n += 1
        return None, None

    @staticmethod
    def gnu_hash(key):
        h = 5381
        for c in key:
            h = h * 33 + ord(c)
        return h & 0xFFFFFFFF
