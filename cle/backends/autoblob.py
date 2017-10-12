from . import Backend, register_backend, Blob
from ..errors import CLEError
import struct
import archinfo
import logging
l = logging.getLogger("cle.autoblob")

__all__ = ('AutoBlob',)

class AutoBlob(Blob):
    """
    A backend that uses heuristics, hacks, magic, and unicorn horn concentrate to figure out what's in your blobs
    It will take a guess as to the base address, entry point, and architecture.
    The rest, however, is up to you!
    You can still give it a hint via the custom_arch, custom_offset, and custom_entry_point params.
    """

    def __init__(self, binary, custom_offset=None, segments=None, **kwargs):
        """
        :param custom_arch:   (required) an :class:`archinfo.Arch` for the binary blob.
        :param custom_offset: Skip this many bytes from the beginning of the file.
        :param segments:      List of tuples describing how to map data into memory. Tuples
                              are of ``(file_offset, mem_addr, size)``.

        You can't specify both ``custom_offset`` and ``segments``.
        """
        Backend.__init__(self, binary, **kwargs)
        arch, base, entry = AutoBlob.autodetect_initial(self.binary_stream)

        if self.arch is None:
            if arch is None:
                raise CLEError("AutoBlob couldn't determine your arch.  Try specifying one.!")
            self.set_arch(arch)

        self.linked_base = kwargs.get('custom_base_addr', base)
        if self.linked_base is None:
            l.warning("AutoBlob could not detect the base address.  Assuming 0")
            self.linked_base = 0
        self.mapped_base = self.linked_base
        l.error(hex(self.mapped_base))
        self._entry = self._custom_entry_point if self._custom_entry_point is not None else entry
        if self._entry is None:
            l.warning("Autoblob could not detect the entry point, assuming 0")
            self._entry = 0

        self._min_addr = 2**64
        self._max_addr = 0 #TODO: This doesn't look right
        self.os = 'unknown' # TODO: Let this be specified somehow

        # TODO: Actually use this
        """
        if custom_offset is not None:
            if segments is not None:
                l.error("You can't specify both custom_offset and segments. Taking only the segments data")
            else:
                self.binary_stream.seek(0, 2)
                segments = [(custom_offset, 0, self.binary_stream.tell() - custom_offset)]
        else:
            if segments is not None:
                pass
            else:
                self.binary_stream.seek(0, 2)
                segments = [(0, self.linked_base, self.binary_stream.tell())]
        """
        self.binary_stream.seek(0, 2)
        segments = [(0, self.linked_base, self.binary_stream.tell())]
        for file_offset, mem_addr, size in segments:
            self._load(file_offset, mem_addr, size)

    @staticmethod
    def is_compatible(stream):
        arch, base, entry = AutoBlob.autodetect_initial(stream)
        if arch and base and entry:
            l.info("AutoBlob thinks the arch is %s, the base address is %#08x, and the entry point is %#08x, and will"
                   "now try to load the binary.  If this is wrong, you can manually use the Blob loader backend to"
                   "specify custom parameters" % (arch, base, entry))
            return True
        return False

    @staticmethod
    def autodetect_initial(stream):
        """
        Pre-loading autodetection code should go here.
        All funcs operate on the file stream
        This will include:
        - What architecture is it?
        - What's the base address?
        - What's the entry point?

        :return:
        """
        arch = None
        base = None
        entry = None
        try:
            for heur in AutoBlob.initial_heuristics:
                if arch is not None and base is not None and entry is not None:
                    break
                a, b, e = heur(stream)
                arch = a if arch is None else arch
                base = b if base is None else base
                entry = e if entry is None else entry
            return arch, base, entry
        except:
            l.exception(" ")
            return None, None, None
        finally:
            stream.seek(0)

    def autodetect_secondary(self):
        """
        Dig up as much info about the just-loaded binary as possible.
        If we didn't find the IVT before, can we find it now?
        If we didn't pin down the exact arch revision, can we do that?
        Also, some fingerprinting on the entry function itself may yield more info.

        :return:
        """
        pass


    def detect_arm_ivt(stream):
        """

        :param stream:
        :type stream: file
        :return:
        """
        min_arm_sp = 0x20000000
        max_arm_sp = 0x20100000

        # TODO: We're just looking at the front for now
        try:
            maybe_sp = stream.read(4)
            maybe_le_sp = struct.unpack('<I', maybe_sp)[0]
            maybe_be_sp = struct.unpack(">I", maybe_sp)[0]
            if min_arm_sp < maybe_le_sp < max_arm_sp:
                maybe_arch = archinfo.ArchARMEL(endness=archinfo.Endness.LE)
                l.debug("Found possible Little-Endian ARM IVT with initial SP %#08x" % maybe_le_sp)
                maybe_entry = struct.unpack('<I', stream.read(4))[0]
                l.debug("Reset vector at %#08x" % maybe_entry)
                maybe_base = maybe_entry & 0xffff0000 # A complete guess
                l.debug("Guessing base address at %#08x" % maybe_base)
                return maybe_arch, maybe_base, maybe_entry
            elif min_arm_sp < maybe_be_sp < max_arm_sp:
                maybe_arch = archinfo.ArchARM(endness=archinfo.Endness.BE)
                l.debug("Found possible Big-Endian ARM IVT with initial SP %#08x" % maybe_be_sp)
                maybe_entry = struct.unpack('>I', stream.read(4))[0]
                l.debug("Reset vector at %#08x" % maybe_entry)
                maybe_base = maybe_entry & 0xffff0000  # A complete guess
                l.debug("Guessing base address at %#08x" % maybe_base)
                return maybe_arch, maybe_base, maybe_entry
            else:
                # Nope
                return (None, None, None)
        except:
            l.exception("Something died")
            return (None, None, None)
        finally:
            stream.seek(0)

    initial_heuristics = [detect_arm_ivt]


register_backend("autoblob", AutoBlob)
