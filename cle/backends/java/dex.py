from __future__ import annotations

import logging

from cle.backends.backend import register_backend
from cle.errors import CLEError

from .soot import Soot

log = logging.getLogger(name=__name__)


class Dex(Soot):
    """
    Backend for lifting bare DEX files to Soot.
    """

    is_default = True  # let CLE automatically use this backend

    def __init__(
        self,
        dex_path,
        binary_stream,
        entry_point=None,
        entry_point_params=(),
        android_sdk=None,
        android_api_version=None,
        **options,
    ):
        """
        :param dex_path:                Path to the DEX file.
        :param android_sdk:             Path to Android SDK folder (e.g. "/home/angr/android/platforms")
        :param android_api_version:     Android API level to resolve the Android class library against. An APK
                                        declares this in its manifest; a bare DEX file has no manifest, so it
                                        has to be given here.

        The following parameters are optional

        :param entry_point:             Fully qualified name of method that should be used as the entry point.
                                        A bare DEX file declares no components, so there is none by default.
        """

        log.info("Loading DEX from %s ...", dex_path)

        example = (
            '    loading_opts = { "android_sdk" : "/home/angr/android/platforms",\n'
            '                     "android_api_version" : 35 }\n'
            '    proj = angr.Project("/path/to/classes.dex", main_opts=loading_opts)'
        )
        if not android_sdk:
            raise CLEError("\nPath to Android SDK must be specified explicitly, e.g.\n" + example)
        if android_api_version is None:
            raise CLEError(
                "\nA bare DEX file has no manifest declaring an Android API level, so "
                "android_api_version must be specified explicitly, e.g.\n" + example
            )

        # the actual lifting is done by the Soot superclass
        super().__init__(
            dex_path,
            binary_stream,
            input_format="dex",
            android_sdk=android_sdk,
            android_api_version=android_api_version,
            entry_point=entry_point,
            entry_point_params=entry_point_params,
            **options,
        )

    @classmethod
    def is_compatible(cls, stream) -> bool:
        stream.seek(0)
        identstring = stream.read(4)
        stream.seek(0)
        return identstring == b"dex\n"


register_backend("dex", Dex)
