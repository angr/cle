from __future__ import annotations

import logging
import os
from unittest import mock

import cle
from cle.backends.cartfile import CARTFile
from cle.backends.elf.elf import ELF

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

FAUXWARE = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware")


def raise_after_reading(stream):
    stream.read(100)
    raise ValueError("this probe cannot answer for these bytes")


def test_a_raising_probe_does_not_stop_a_later_backend():
    with mock.patch.object(CARTFile, "is_compatible", side_effect=raise_after_reading):
        ld = cle.Loader(FAUXWARE, auto_load_libs=False)

    assert isinstance(ld.main_object, cle.ELF)
    assert ld.main_object.entry == cle.Loader(FAUXWARE, auto_load_libs=False).main_object.entry


def test_a_raising_probe_is_reported(caplog):
    with mock.patch.object(CARTFile, "is_compatible", side_effect=raise_after_reading):
        with caplog.at_level(logging.WARNING, logger="cle.loader"):
            cle.Loader(FAUXWARE, auto_load_libs=False)

    reports = [record for record in caplog.records if "CARTFile" in record.getMessage()]
    assert reports, "the backend that could not answer is not named in the log"
    assert reports[0].levelno == logging.WARNING
    assert "this probe cannot answer for these bytes" in reports[0].getMessage()


def test_the_next_probe_sees_the_stream_from_the_start():
    unpatched = ELF.is_compatible
    positions = []

    def record_position(stream):
        positions.append(stream.tell())
        return unpatched(stream)

    with (
        mock.patch.object(CARTFile, "is_compatible", side_effect=raise_after_reading),
        mock.patch.object(ELF, "is_compatible", side_effect=record_position),
    ):
        ld = cle.Loader(FAUXWARE, auto_load_libs=False)

    assert isinstance(ld.main_object, cle.ELF)
    assert positions and set(positions) == {0}
