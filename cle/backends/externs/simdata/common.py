from . import SimData
from ...relocation import Relocation

class PointTo(SimData):
    pointto_name: str = NotImplemented
    pointto_type: int = NotImplemented
    type = SimData.TYPE_OBJECT

    @staticmethod
    def static_size(arch):
        return arch.bytes

    def value(self):
        return bytes(self.size)

    def relocations(self):
        return [SimpleRelocation(self.owner, self.owner.make_import(self.pointto_name, self.pointto_type), self.relative_addr)]


class SimpleRelocation(Relocation):
    @property
    def value(self):
        return self.resolvedby.rebased_addr