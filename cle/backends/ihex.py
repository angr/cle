import re
import logging
import binascii
import struct

from . import register_backend, Backend
from ..errors import CLEError

l = logging.getLogger(name=__name__)

__all__ = ('Hex',)

intel_hex_re = re.compile(b":([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F])"
                          b"([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F]+)*([0-9a-fA-F][0-9a-fA-F])")

HEX_TYPE_DATA = 0x00
HEX_TYPE_EOF = 0x01
HEX_TYPE_EXTSEGADDR = 0x02
HEX_TYPE_STARTSEGADDR = 0x03
HEX_TYPE_EXTLINEARADDR = 0x04
HEX_TYPE_STARTLINEARADDR = 0x05

if bytes is not str:
    chh = lambda x: x
else:
    chh = ord


class Hex(Backend):
    """
    A loader for Intel Hex Objects
    See https://en.wikipedia.org/wiki/Intel_HEX
    """
    is_default = True # Tell CLE to automatically consider using the Hex backend

    @staticmethod
    def parse_record(line):
        m = intel_hex_re.match(line)
        if not m:
            raise CLEError("Invalid HEX record: " + line)
        my_cksum = 0
        count, addr, rectype, data, cksum = m.groups()
        cksum = int(cksum, 16)
        for d in binascii.unhexlify(line[1:-2]):
            my_cksum = (my_cksum + chh(d)) % 256
        my_cksum = ((my_cksum ^ 0xff) + 1) % 256
        if my_cksum != cksum:
            raise CLEError("Invalid checksum: Computed %s, found %s" % (hex(my_cksum), hex(cksum)))
        count = int(count, 16)
        addr = int(addr, 16)
        rectype = int(rectype, 16)
        if data:
            data = binascii.unhexlify(data)
        if data and count != len(data):
            raise CLEError("Data length field does not match length of actual data: " + line)
        return rectype, addr, data

    @staticmethod
    def coalesce_regions(regions):
        # Lots of tiny memory regions is bad!
        # The greedy algorithm to smash them together:
        result = []
        for addr, region in sorted(regions):
            if result and result[-1][0] + len(result[-1][1]) == addr:
                result[-1] = (result[-1][0], result[-1][1] + region)
            else:
                result.append((addr, region))

        return result

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Do the whole thing in one shot.
        self.os = 'unknown'
        got_base = False
        got_entry = False
        self._binary_stream.seek(0)
        string = self._binary_stream.read()
        recs = string.splitlines()
        regions = []
        max_addr = 0
        min_addr = 0xffffffffffffffff
        self._base_address = 0
        for rec in recs:
            rectype, addr, data = Hex.parse_record(rec)
            if rectype == HEX_TYPE_DATA:
                addr += self._base_address
                #l.debug("Loading %d bytes at " % len(data) + hex(addr))
                # Raw data.  Put the bytes
                regions.append((addr, data))
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
                self._base_address = struct.unpack('>H', data)[0] * 16
                got_base = True
                l.debug("Loading a segment at %#x", self._base_address)
            elif rectype == HEX_TYPE_STARTSEGADDR:
                # Four bytes, the segment and the initial IP
                got_base = True
                got_entry = True
                self._initial_cs, self._initial_ip = struct.unpack('>HH', data)
                # The whole thing is the entry, as far as angr is concerned.
                self._entry = struct.unpack('>I', data)[0]
                l.debug("Got entry point at %#x", self._entry)
            elif rectype == HEX_TYPE_EXTLINEARADDR:
                got_base = True
                # Specifies the base for all future data bytes.
                self._base_address = struct.unpack('>H', data)[0] << 16
                l.debug("Loading a segment at %#x", self._base_address)
            elif rectype == HEX_TYPE_STARTLINEARADDR:
                got_entry = True
                # The 32-bit EIP, really the same as STARTSEGADDR, but some compilers pick one over the other.
                self._entry = struct.unpack('>I', data)[0]
                l.debug("Found entry point at %#x", self._entry)
                self._initial_eip = self._entry
            else:
                raise CLEError("This HEX Object type is not implemented: " + hex(rectype))
        if not got_base:
            l.warning("No base address was found in this HEX object file. It is assumed to be 0")
        if not got_entry:
            l.warning("No entry point was found in this HEX object file, and it is assumed to be 0. "
                      "Specify one with `entry_point` to override.")
        # HEX specifies a ton of tiny little memory regions.  We now smash them together to make things faster.
        new_regions = Hex.coalesce_regions(regions)
        for addr, data in new_regions:
            self.memory.add_backer(addr, data)
        self._max_addr = max_addr
        self._min_addr = min_addr

    @staticmethod
    def is_compatible(stream):
        stream.seek(0)
        s = stream.read(0x10)
        stream.seek(0)
        return s.startswith(b":")

register_backend("hex", Hex)
