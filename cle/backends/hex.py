
import re
from . import register_backend
from ..errors import CLEError
from .blob import Blob

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

    def __init__(self, path, custom_arch=None, custom_entry_point=0, *args, **kwargs):
        super(Hex, self).__init__(path, custom_arch=custom_arch, custom_entry_point=custom_entry_point, **kwargs)
        self._entry = None

    @staticmethod
    def parse_record(line):
        m = intel_hex_re.match(line)
        if not m:
            raise CLEError("Invalid HEX record: " + line)
        count, addr, rectype, data, cksum = m.groups()
        count = int(count, 16)
        addr = int(addr, 16)
        rectype = int(rectype, 16)
        if data:
            data = data.decode('hex')
        if data and count != len(data):
            raise CLEError("Data length field does not match length of actual data: " + line)
        # TODO: Verify checksum if we care
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
        self.binary_stream.seek(0)
        string = self.binary_stream.read()
        recs = string.splitlines()
        regions = {}
        max_addr = 0
        min_addr = 0xffffffffffffffff
        for rec in recs:
            rectype, addr, data = Hex.parse_record(rec)
            if rectype == HEX_TYPE_DATA:
                # Raw data.  Put the bytes
                regions.update({addr: data})
                # We have to be careful about the min and max addrs
                if addr < min_addr:
                    min_addr = addr
                if addr + len(data) > max_addr:
                    max_addr = addr + len(data)
            elif rectype == HEX_TYPE_EOF:
                # EOF
                break
            elif rectype == HEX_TYPE_STARTSEGADDR:
                self._entry = int(data.encode('hex'),16)
                self._custom_entry_point = self._entry
            else:
                raise CLEError("This HEX Object type is not implemented: " + hex(rectype))
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
