from __future__ import annotations

from pathlib import Path

import pytest

import cle
from cle.errors import CLECompatibilityError

SREC_FIXTURES = Path(__file__).resolve().parents[2] / "binaries" / "tests" / "srec"


def test_srec_compatibility_requires_a_valid_record():
    with (SREC_FIXTURES / "rcr_test.srec").open("rb") as stream:
        assert cle.SRec.is_compatible(stream)
        assert stream.tell() == 0

    with (SREC_FIXTURES / "not_srec.sql").open("rb") as stream:
        assert not cle.SRec.is_compatible(stream)
        assert stream.tell() == 0


def test_srec_false_positive_does_not_select_the_backend():
    with pytest.raises(CLECompatibilityError, match="Unable to find a loader backend"):
        cle.Loader(SREC_FIXTURES / "not_srec.sql", auto_load_libs=False)
