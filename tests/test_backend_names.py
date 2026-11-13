from __future__ import annotations

import os

import pytest

import cle
from cle.backends import ALL_BACKENDS

TEST_BASE = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.join("..", "..", "binaries"))

# A GCC-ARM static archive of 43 ELF objects. Its R_ARM_THM_CALL relocations only reach between members
# when the members are packed more tightly than the default granularity.
ARCHIVE = os.path.join(
    TEST_BASE,
    "tests_src",
    "i2c_master_read-nucleol152re",
    "mbed",
    "TARGET_NUCLEO_L152RE",
    "TOOLCHAIN_GCC_ARM",
    "libmbed.a",
)
OBJECT_FILE = os.path.join(TEST_BASE, "tests", "x86_64", "fauxware.obj")
FATBIN = os.path.join(TEST_BASE, "tests", "multi_arch", "fauxware_macho_multiarch")

TARGETS = {
    cle.StaticArchive: (ARCHIVE, {"rebase_granularity": 0x1000}),
    cle.Coff: (OBJECT_FILE, {}),
    cle.Universal2: (FATBIN, {}),
}


def load_as(backend_cls, name):
    path, loader_opts = TARGETS[backend_cls]
    return cle.Loader(path, main_opts={"backend": name}, auto_load_libs=False, **loader_opts)


def test_every_registered_backend_name_is_lowercase():
    assert [name for name in ALL_BACKENDS if name != name.lower()] == []


@pytest.mark.parametrize(
    ("backend_cls", "name"),
    [(cle.StaticArchive, "ar"), (cle.Coff, "coff"), (cle.Universal2, "universal2")],
)
def test_a_backend_is_selectable_by_its_lowercase_name(backend_cls, name):
    assert type(load_as(backend_cls, name).main_object) is backend_cls


@pytest.mark.parametrize(
    ("backend_cls", "name"),
    [(cle.StaticArchive, "AR"), (cle.Coff, "COFF"), (cle.Universal2, "Universal2")],
)
def test_the_spellings_recorded_in_existing_databases_still_resolve(backend_cls, name):
    """
    angr's .adb serializer stores the registered name and passes it back as main_opts["backend"] when the
    database is reopened, so databases written before these names were lowercased still carry these.
    """
    assert type(load_as(backend_cls, name).main_object) is backend_cls


def test_an_unregistered_backend_name_is_still_rejected():
    with pytest.raises(cle.CLEError, match="Invalid backend: nope"):
        cle.Loader(OBJECT_FILE, main_opts={"backend": "nope"}, auto_load_libs=False)
