from . import SimData, register
from .common import PointTo

class DummyProgname(SimData):
    name = '_dummy_progname'
    type = SimData.TYPE_OBJECT
    libname = 'libc.so.6'

    progname = b'./program\0'

    @classmethod
    def static_size(cls, arch):
        return len(cls.progname)

    def value(self):
        return self.progname

class Progname(PointTo):
    pointto_name = '_dummy_progname'
    pointto_type = SimData.TYPE_OBJECT
    name = '__progname'
    libname = 'libc.so.6'
    type = SimData.TYPE_OBJECT
    addend = 2

class PrognameFull(PointTo):
    pointto_name = '_dummy_progname'
    pointto_type = SimData.TYPE_OBJECT
    name = '__progname_full'
    libname = 'libc.so.6'
    type = SimData.TYPE_OBJECT
    addend = 0

register(DummyProgname)
register(Progname)
register(PrognameFull)
