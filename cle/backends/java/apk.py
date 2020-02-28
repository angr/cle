import logging
import os
import tempfile
from zipfile import ZipFile

from .. import register_backend
from .soot import Soot

l = logging.getLogger(name=__name__)

# Default list of JNI archs (in descending order of preference)
# => specifies which arch should be used for loading native libs from the APK
default_jni_archs = ['x86', 'armeabi', 'armeabi-v7a', 'x86_64', 'arm64-v8a']


class Apk(Soot):
    """
    Backend for lifting Apk's to Soot.
    """

    is_default = True  # let CLE automatically use this backend

    def __init__(self, apk_path, binary_stream, entry_point=None, entry_point_params=(), android_sdk=None,
                 supported_jni_archs=None, jni_libs=None, jni_libs_ld_path=None, **options):
        """
        :param apk_path:                Path to APK.
        :param android_sdk:             Path to Android SDK folder (e.g. "/home/angr/android/platforms")

        The following parameters are optional

        :param entry_point:             Fully qualified name of method that should be used as the entry point.
        :param supported_jni_archs:     List of supported JNI architectures (ABIs) in descending order of preference.
        :param jni_libs:                Name(s) of JNI libs to load (if any). If not specified, we try to extract
                                        JNI libs from the APK.
        :param jni_libs_ld_path:        Path(s) where to find libs defined by param jni_libs.
                                        Note: Directory of the APK is added by default.
        """

        l.info("Loading APK from %s ...", apk_path)

        if not android_sdk:
            raise ValueError('\nPath to Android SDK must be specified explicitly, e.g.\n'
                             '    loading_opts = { "android_sdk" : "/home/angr/android/platforms" }\n'
                             '    proj = angr.Project("/path/to/apk/target.apk", main_opts=loading_opts)')

        if not supported_jni_archs:
            supported_jni_archs = default_jni_archs

        # if jni libs are not defined by the user, we try to extract them from the APK
        if not jni_libs:
            l.info("No JNI libs provided. Trying to parse them from the APK.")
            jni_libs, jni_libs_ld_path = self._extract_jni_libs(apk_path, supported_jni_archs)
        else:
            l.info("Using user defined JNI lib(s) %s (load path(s) %s)", jni_libs, jni_libs_ld_path)

        if not entry_point:
            try:
                from pyaxmlparser import APK as APKParser
                apk_parser = APKParser(apk_path)
                main_activity = apk_parser.get_main_activity()
                entry_point = main_activity + '.' + 'onCreate'
                entry_point_params = ('android.os.Bundle',)
            except ImportError:
                l.error("Install pyaxmlparser to identify APK entry point.")

        # the actual lifting is done by the Soot superclass
        super().__init__(apk_path, binary_stream,
                                  input_format='apk',
                                  android_sdk=android_sdk,
                                  entry_point=entry_point,
                                  entry_point_params=entry_point_params,
                                  jni_libs=jni_libs,
                                  jni_libs_ld_path=jni_libs_ld_path,
                                  **options)


    @staticmethod
    def _extract_jni_libs(apk_path, supported_jni_archs):
        """
        Extract JNI libs from APK.

        If an APK uses native libraries via JNI, the APK usually include the libs compiled for
        various architectures. This method first matches the available archs with the list of
        supported archs and then extracts the JNI libs using one of the matched archs.

        :return: Name of all extracted JNI libs together with the path to the directory used for
                 extracting.
        :rtype: tuple
        """
        with ZipFile(apk_path) as apk:
            # Step 1: get filelist from APK
            # => structure follows this schema:
            #    AndroidManifest.xml
            #    META-INF/MANIFEST.MF
            #    classes.dex
            #    lib/armeabi-v7a/libnative-lib.so
            #    lib/x86/libnative-lib.so
            filelist = apk.namelist()

            # Step 2: parse name of available libs and archs
            #         from lib paths "/lib/<jni_arch>/lib<name>.so"
            lib_filelist = [f.split('/') for f in filelist if f.startswith('lib')]
            jni_libs = { lib_path[2] for lib_path in lib_filelist }
            available_jni_archs = { lib_path[1] for lib_path in lib_filelist }

            if not jni_libs:
                l.info("No JNI libs found.")
                return None, None
            l.info("Found JNI lib(s): %s",", ".join(jni_libs))

            # Step 3: get the first supported jni arch that is available in the APK
            jni_archs = [arch for arch in supported_jni_archs
                            if  arch in available_jni_archs]
            if not jni_archs:
                raise ValueError("Couldn't find a supported JNI arch. Available %s. Supported %s."
                                 "" % (available_jni_archs, supported_jni_archs))
            jni_arch = jni_archs[0]
            l.info("Libs are available with arch(s): %s. Picking %s.", ", ".join(available_jni_archs), jni_arch)

            # Step 4: extract all used libaries from the APK
            # TODO: implement this w/o the need of actually writing files to disk
            #       see https://github.com/angr/cle/issues/123
            tmp_dir = tempfile.mkdtemp()
            for lib in jni_libs:
                apk_file = "lib/{jni_arch}/{lib_name}".format(jni_arch=jni_arch, lib_name=lib)
                apk.extract(apk_file, path=tmp_dir)
            jni_libs_ld_path = os.path.join(tmp_dir, 'lib', jni_arch)

            l.info("Extracted lib(s) to %s", jni_libs_ld_path)
            return jni_libs, jni_libs_ld_path

    @staticmethod
    def is_compatible(stream):
        # check if stream is an archive
        if not Soot.is_zip_archive(stream):
            return False
        # get filelist
        with ZipFile(stream) as apk:
            filelist = apk.namelist()
        # check for manifest and the .dex bytecode file
        if 'AndroidManifest.xml' not in filelist:
            return False
        if 'classes.dex' not in filelist:
            return False
        return True

register_backend('apk', Apk)
