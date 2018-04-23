from .. import register_backend

from .soot import Soot

import logging
_l = logging.getLogger("cle.backends.apk")

class Apk(Soot):

    """
    Backend for lifting Apk's to Soot.
    """

    is_default = True # let CLE automatically use this backend

    def __init__(self, path, main_class=None, loader=None,
                 native_libs=None, native_libs_ld_path=None, **options):

        """
        :param main_class:              If no main class is specified, we try to parse it from the manifest.
        """

        if native_libs or native_libs_ld_path:
            _l.warning("Native libraries are set automatically and given parameters get overwritten.")
            # TODO parse apk and match native libs
            # * Usually libs are included for various archs in the apks
            #   => might look for a default arch (e.g. ARM) + fallbacks if not available + user option
            # * Problem: dependencies are specified by a path to a file 
            #            => Option 1: https://github.com/angr/cle/issues/123 
            #            => Option 2: extract apk to a tmp folder

        if not main_class:
            # TODO find main class
            pass

        # the actual lifting is done by the Soot superclass
        # TODO it might be necessary to specify the path to android sdk 
        #      (see example apk's in pysoot project)
        super(Apk, self).__init__(path,
                                  main_class=main_class,
                                  native_libs=native_libs,
                                  native_libs_ld_path=native_libs_ld_path,
                                  **options)

    @staticmethod
    def is_compatible(stream):
        # TODO check for android manifest and .dex classses
        return False

register_backend('apk', Apk)
