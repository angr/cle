
import re
from . import register_backend
from ..errors import CLEError
from .blob import Blob

import logging
l = logging.getLogger("cle.hex")

__all__ = ('Hex',)

intel_hex_re = re.compile(":([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F]+)*([0-9a-fA-F][0-9a-fA-F])")

HEX_TYPE_DATA = 0x00
HEX_TYPE_EOF = 0x01
HEX_TYPE_EXTSEGADDR = 0x02
HEX_TYPE_STARTSEGADDR = 0x03
HEX_TYPE_EXTLINEARADDR = 0x04
HEX_TYPE_STARTLINEARADDR = 0x05

class Hex(Blob):
    """
    A loader for Intel Hex Objects
    See https://en.wikipedia.org/wiki/Intel_HEX
    """

    def __init__(self, path, custom_arch=None, custom_entry_point=0, **kwargs):
        super(Hex, self).__init__(path, custom_arch=custom_arch, custom_entry_point=custom_entry_point, **kwargs)
        self._entry = None

    @staticmethod
    def parse_record(line):
        m = intel_hex_re.match(line)
        if not m:
            raise CLEError("Invalid HEX record: " + line)
        my_cksum = 0
        count, addr, rectype, data, cksum = m.groups()
        cksum = int(cksum, 16)
        for d in line[1:-2].decode('hex'):
            my_cksum = (my_cksum + ord(d)) % 256
        my_cksum = ((my_cksum ^ 0xff) + 1) % 256
        if my_cksum != cksum:
            raise CLEError("Invalid checksum: Computed %s, found %s" % (hex(my_cksum), hex(cksum)))
        count = int(count, 16)
        addr = int(addr, 16)
        rectype = int(rectype, 16)
        if data:
            data = data.decode('hex')
        if data and count != len(data):
            raise CLEError("Data length field does not match length of actual data: " + line)
        return rectype, addr, data

    @staticmethod
    def coalesce_regions(regions):
        # Lots of tiny memory regions is bad!
        # The greedy algorithm to smash them together:
        x = 0
        while x < len(regions.keys()):
            a = regions.keys()[x]
            d = regions[regions.keys()[x]]
            if a + len(d) in regions:
                d2 = regions[a + len(d)]
                regions.pop(a + len(d))
                d += d2
                regions.update({a: d})
            else:
                x += 1
        return regions

    def _load(self, file_offset, mem_addr, size):

        # Ignore the params, they don't really work in this format.
        # Do the whole thing in one shot.
        got_base = False
        got_entry = False
        self.binary_stream.seek(0)
        string = self.binary_stream.read()
        recs = string.splitlines()
        regions = {}
        max_addr = 0
        min_addr = 0xffffffffffffffff
        self._base_address = 0
        for rec in recs:
            rectype, addr, data = Hex.parse_record(rec)
            if rectype == HEX_TYPE_DATA:
                addr += self._base_address
                #l.debug("Loading %d bytes at " % len(data) + hex(addr))
                # Raw data.  Put the bytes
                regions.update({addr: data})
                # We have to be careful about the min and max addrs
                if addr < min_addr:
                    min_addr = addr
                if addr + len(data) > max_addr:
                    max_addr = addr + len(data)
            elif rectype == HEX_TYPE_EOF:
                # EOF
                l.debug("Got EOF record.")
                break
            elif rectype == HEX_TYPE_EXTSEGADDR:
                # "Extended Mode" Segment address, take this value, multiply by 16, make the base
                self._base_address = int(data.decode('hex'), 16) * 16
                got_base = True
                l.debug("Loading a segment at " + hex(self._base_address))
            elif rectype == HEX_TYPE_STARTSEGADDR:
                # Four bytes, the segment and the initial IP
                got_base = True
                got_entry = True
                self._initial_cs = int(data[:2].encode('hex'), 16)
                self._initial_ip = int(data[2:].encode('hex'), 16)
                # The whole thing is the entry, as far as angr is concerned.
                self._entry = int(data.encode('hex'), 16)
                self._custom_entry_point = self._entry
                l.debug("Got entry point at " + hex(self._entry))
            elif rectype == HEX_TYPE_EXTLINEARADDR:
                got_base = True
                # Specifies the base for all future data bytes.
                self._base_address = int(data.encode('hex'), 16) << 16
                l.debug("Loading a segment at " + hex(self._base_address))
            elif rectype == HEX_TYPE_STARTLINEARADDR:
                got_entry = True
                # The 32-bit EIP, really the same as STARTSEGADDR, but some compilers pick one over the other.
                self._entry = int(data.encode('hex'), 16)
                l.debug("Found entry point at " + hex(self._entry))
                self._initial_eip = self._entry
                self._custom_entry_point = self._entry
            else:
                raise CLEError("This HEX Object type is not implemented: " + hex(rectype))
        if not got_base:
            l.warning("No base address was found in this HEX object file. It is assumed to be 0")
        if not got_entry:
            l.warning("No entry point was found in this HEX object file, and it is assumed to be 0. "
                      "Specify one with `custom_entry_point` to override.")
        # HEX specifies a ton of tiny little memory regions.  We now smash them together to make things faster.
        new_regions = Hex.coalesce_regions(regions)
        for addr, data in new_regions.items():
            self.memory.add_backer(addr, data)
        self._max_addr = max_addr
        self._min_addr = min_addr

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        s = stream.read(0x10)
        stream.seek(0)
        return s.startswith(":")

register_backend("hex", Hex)
