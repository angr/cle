from . import SimData, register
from .common import PointTo, StaticWord

class DummyProgname(SimData):
    name = '_dummy_progname'
    type = SimData.TYPE_OBJECT
    libname = 'libc.so.6'

    progname = b'./program\0'

    @classmethod
    def static_size(cls, owner):
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

class EnvironmentPointer(StaticWord):
    name = '__environ'
    libname = 'libc.so.6'
    word = 0

class EnvironmentPointerAlso(StaticWord):
    name = 'environ'
    libname = 'libc.so.6'
    word = 0

class OptInd(StaticWord):
    name = 'optind'
    libname = 'libc.so.6'
    word = 1
    wordsize = 4

class OptArg(StaticWord):
    name = 'optarg'
    libname = 'libc.so.6'
    word = 0

class LibcStackEnd(StaticWord):
    name = '__libc_stack_end'
    libname = 'ld-linux.so.2' # TODO THERE ARE MORE NAMES THAN THIS
    word = 0

register(DummyProgname)
register(Progname)
register(PrognameFull)
register(EnvironmentPointer)
register(EnvironmentPointerAlso)
register(OptInd)
register(OptArg)
register(LibcStackEnd)
