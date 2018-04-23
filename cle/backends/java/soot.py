
import archinfo
from archinfo.arch_soot import SootMethodDescriptor, SootAddressDescriptor

try:
    import pysoot
    from pysoot.lifter import Lifter
except ImportError:
    pysoot = None

from .. import Backend
from ...errors import CLEError

import logging
_l = logging.getLogger("cle.backends.soot")


class Soot(Backend):

    """
    The basis loader class for lifting Java code from Jar's and Apk's to Soot.
    """

    def __init__(self, path, main_class=None,
                 additional_jars=None, additional_jar_roots=None,
                 native_libs_ld_path=None, native_libs=None,
                 **kwargs):
 
        """
        :param path:                    Path to the main jar or apk.

        The following parameters are optional

        :param main_class:              Name of class containing the main method, which should be used as entry point.

        :param additional_jars:         Additional Jars.
        :param additional_jar_roots:    Additional Jar roots.

        :param native_libs:             Name(s) if libraries containing native code components (JNI)
        :param native_libs_ld_path:     Path(s) where to find native libraries. Note: Requires use_system_libs=True
        """

        if not pysoot:
            raise ImportError('Cannot import PySoot. The Soot backend requires PySoot to function. '
                              'Please install PySoot first.')

        if kwargs.get('has_memory', False):
            raise CLEError('The parameter "has_memory" must be False for Soot backend.')

        super(Soot, self).__init__(path, has_memory=False, **kwargs)

        # load the classes
        pysoot_lifter = Lifter(path,
                               additional_jars=additional_jars,
                               additional_jar_roots=additional_jar_roots
                               )
        self._classes = pysoot_lifter.classes

        # find entry method
        try:
            main_method_descriptor = SootMethodDescriptor.from_method(next(self.get_method("main", main_class)))
            entry = SootAddressDescriptor(main_method_descriptor, 0, 0)
        except CLEError:
            _l.warning('Failed to identify the entry (the Main method).')
            entry = None

        self._entry = entry
        self.os = 'javavm'
        self.rebase_addr = None
        self.set_arch(archinfo.arch_from_id('soot'))

        # automatically load nativ libraries (with CLE) by adding them as a dependency of this object
        if native_libs:
            self.deps += [native_libs] if type(native_libs) in (str, unicode) else native_libs
            # if available, add additional load path(s)
            if native_libs_ld_path:
                path_list = [native_libs_ld_path] if type(native_libs_ld_path) in (str, unicode) else native_libs_ld_path
                self.extra_load_path += path_list

    @property
    def max_addr(self):
        # FIXME: This is a hack to satisfy checks elsewhere that max_addr must be greater than min_addr
        return self.min_addr + 1

    @property
    def entry(self):
        return self._entry

    @property
    def classes(self):
        return self._classes

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
