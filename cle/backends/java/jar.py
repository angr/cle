import zipfile

from .. import register_backend

from .soot import Soot

import logging
l = logging.getLogger("cle.backends.jar")

class Jar(Soot):

    """
    Backend for lifting Jar's to Soot.
    """

    is_default = True # let CLE automatically use this backend

    def __init__(self, path, main_class=None, loader=None,
                 native_libs=None, native_libs_ld_path=None, **options):

        """
        :param main_class:              If no main class is specified, we try to parse it from the manifest.

        :param additional_jars:         See Soot Backend.
        :param additional_jar_roots:    See Soot Backend.

        :param native_libs:             See Soot Backend.
        :param native_libs_ld_path:     See Soot Backend.
        """

        if native_libs and not loader.auto_load_libs:
            l.warning("To load native libraries, auto_load_libs must be true.")

        if not main_class:
            # try to parse main class from the manifest
            self.manifest = self.get_manifest(path)
            main_class = self.manifest.get('Main-Class', None)

        # the actual lifting is done by the Soot superclass
        super(Jar, self).__init__(path,
                                  main_class=main_class,
                                  native_libs=native_libs,
                                  native_libs_ld_path=native_libs_ld_path,
                                  **options)

    @staticmethod
    def is_compatible(stream):
        identstring = stream.read(4)
        stream.seek(0)
        if identstring.startswith('\x50\x4b\x03\x04') and Jar.is_jar(stream):
            return True
        return False

    @staticmethod
    def is_jar(stream):
        z = zipfile.ZipFile(stream)
        for f in z.filelist:
            if f.filename == 'META-INF/MANIFEST.MF':
                return True
        return False

    def get_manifest(self, binary_path=None):
        """
        Load the MANIFEST.MF file

        :return: A dict of meta info
        :rtype:  dict
        """

        path = binary_path if binary_path else self.binary
        z = zipfile.ZipFile(path)

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

register_backend('jar', Jar)
