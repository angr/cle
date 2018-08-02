
import zipfile

import archinfo
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor

try:
    import pysoot
    from pysoot.lifter import Lifter
except ImportError:
    pysoot = None

from . import Backend
from . import register_backend
from ..errors import CLEError

import logging
_l = logging.getLogger("cle.backends.soot")


class Soot(Backend):
    is_default = True # Tell CLE to automatically consider using the Soot backend

    def __init__(self, path, additional_jars=None, additional_jar_roots=None, main_class=None, **kwargs):

        if not pysoot:
            raise ImportError('Cannot import PySoot. The Soot backend requires PySoot to function. '
                              'Please install PySoot first.')

        if kwargs.get('has_memory', False):
            raise CLEError('The parameter "has_memory" must be False for Soot backend.')

        super(Soot, self).__init__(path, has_memory=False, **kwargs)

        if not main_class:
            # parse main_class from the manifest
            self.manifest = self.get_manifest()
            main_class = self.manifest.get('Main-Class', None)

        # load the classes
        pysoot_lifter = Lifter(path,
                               additional_jars=additional_jars,
                               additional_jar_roots=additional_jar_roots,
                               # main_class=main_class,
                               )
        self._classes = pysoot_lifter.classes

        # find entry method
        try:
            main_method_descriptor = SootMethodDescriptor.from_method(next(self.get_method("main", main_class)))
            entry = SootAddressDescriptor(main_method_descriptor, 0, 0)
        except CLEError:
            _l.warning('Failed to identify the entry (the Main method) of this JAR.')
            entry = None
        self._entry = entry
        self.os = 'javavm'
        self.rebase_addr = None
        self.set_arch(archinfo.arch_from_id('soot'))

    @property
    def max_addr(self):
        # FIXME: This is a hack to satisfy checks elsewhere that max_addr must be greater than min_addr
        return self.min_addr + 1

    @staticmethod
    def is_compatible(stream):
        identstring = stream.read(4)
        stream.seek(0)
        if identstring.startswith(b'\x50\x4b\x03\x04') and Soot.is_jar(stream):
            return True
        return False

    @staticmethod
    def is_jar(stream):
        z = zipfile.ZipFile(stream)
        for f in z.filelist:
            if f.filename == 'META-INF/MANIFEST.MF':
                return True
        return False

    @property
    def entry(self):
        return self._entry

    @property
    def classes(self):
        return self._classes

    def get_manifest(self):
        """
        Load the MANIFEST.MF file

        :return: A dict of meta info
        :rtype:  dict
        """

        z = zipfile.ZipFile(self.binary)

        for f in z.filelist:
            if f.filename == 'META-INF/MANIFEST.MF':
                break

        manifest = z.open('META-INF/MANIFEST.MF', "r")

        data = { }

        for l in manifest.readlines():
            if ':' in l:
                key, value = l.split(':')
                key = key.strip()
                value = value.strip()
                data[key] = value

        manifest.close()

        return data

    def get_class(self, cls_name):
        """
        Get a Soot class object.

        :param str cls_name: Name of the class to get.
        :return:             The class object.
        :rtype:              pysoot.soot.SootClass
        """

        try:
            return self._classes[cls_name]
        except KeyError:
            raise CLEError('Class "%s" does not exist.' % cls_name)

    def get_method(self, thing, cls_name=None):
        """
        Get a Soot method object.

        :param thing:           Descriptor or the method, or name of the method.
        :param str class_name:  Name of the class. If not specified, class name can be parsed from method_name.
        :return:                An iterator of all SootMethod objects that satisfy the criteria.
        :rtype:                 iterator
        """

        if isinstance(thing, SootMethodDescriptor):
            cls_name = thing.class_name
            method_name = thing.name
            method_params = thing.params
        elif isinstance(thing, (str, unicode)):
            # parse the method name
            method_name = thing
            if cls_name is None:
                # parse the class name from method_name
                last_dot = method_name.rfind('.')
                if last_dot >= 0:
                    cls_name = method_name[ : last_dot ]
                    method_name = method_name[last_dot + 1 : ]
                else:
                    raise CLEError('Unknown class name for the method.')
            method_params = None
        else:
            raise TypeError('Unsupported type "%s" for the first argument.' % type(thing))

        try:
            cls = self.get_class(cls_name)
        except CLEError:
            raise

        has_method = False
        for method in cls.methods:
            if method.name == method_name:
                if method_params is None or method_params == method.params:
                    has_method = True
                    yield method

        if not has_method:
            raise CLEError('Method "%s" in class "%s" does not exist.' % (method_name, cls_name))

    @property
    def main_methods(self):
        """
        Find all Main methods in this binary.

        :return: All main methods in each class.
        :rtype:  iterator
        """

        for cls in self.classes.values():
            for method in cls.methods:
                if method.name == "main":  # TODO: Check more attributes
                    yield method


register_backend('soot', Soot)
