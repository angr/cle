from __future__ import annotations

import io

import pytest

import cle
from cle.errors import CLEError

# Width of the address field of each record type, in bytes.
_ADDRESS_BYTES = {
    0: 2,
    1: 2,
    2: 3,
    3: 4,
    5: 2,
    6: 3,
    7: 4,
    8: 3,
    9: 2,
}


def _record(record_type: int, address: int, data: bytes = b"", *, byte_count_delta: int = 0) -> bytes:
    """
    Build one S-record. ``byte_count_delta`` corrupts the byte count field without touching anything else.
    """
    address_bytes = address.to_bytes(_ADDRESS_BYTES[record_type], "big")
    byte_count = len(address_bytes) + len(data) + 1 + byte_count_delta
    body = bytes([byte_count]) + address_bytes + data
    checksum = ~sum(body) & 0xFF
    return f"S{record_type}".encode() + body.hex().upper().encode() + f"{checksum:02X}".encode()


def _load(*records: bytes) -> cle.Loader:
    return cle.Loader(io.BytesIO(b"\n".join(records)), auto_load_libs=False, main_opts={"arch": "X86"})


def test_srec_loads_one_byte_data_record():
    loader = _load(_record(1, 0x8020, b"\xe9"), _record(9, 0x8020))

    assert isinstance(loader.main_object, cle.SRec)
    assert loader.main_object.max_addr == 0x8020
    assert loader.memory.load(0x8020, 1) == b"\xe9"


def test_srec_loads_objcopy_output():
    # Three verbatim lines of `objcopy -O srec` output: the header naming the output file, a data
    # record, and the termination record that carries the start address.
    loader = _load(
        b"S010000066617578776172652E73726563B1",
        b"S3110804A0240000000000000000C0870408CB",
        b"S70508048470FA",
    )

    assert loader.main_object.entry == 0x8048470
    assert loader.memory.load(0x804A02C, 4) == b"\xc0\x87\x04\x08"


def test_srec_loads_long_records():
    # objcopy writes the output file name into the S0 header record, so a header record alone routinely
    # carries more data than a record was previously allowed to hold.
    data = bytes(range(40))
    loader = _load(
        _record(0, 0, b"a-file-name-long-enough-to-need-a-big-record"),
        _record(1, 0x1000, data),
        _record(9, 0x1000),
    )

    assert loader.memory.load(0x1000, len(data)) == data
    assert loader.main_object.max_addr == 0x1000 + len(data) - 1


def test_srec_ignores_a_data_record_that_carries_no_data():
    # An empty data field is well formed; the record simply describes no memory.
    loader = _load(_record(1, 0x2000), _record(1, 0x1000, b"\x90\x90"), _record(9, 0x1000))

    srec = loader.main_object
    assert isinstance(srec, cle.SRec)
    assert srec.regions == [(0x1000, 2)]
    assert srec.max_addr == 0x1001


@pytest.mark.parametrize("record_type", (1, 2, 3))
def test_srec_loads_data_record_of_every_address_width(record_type):
    loader = _load(_record(record_type, 0x1000, b"\x90\x90"), _record(9, 0x1000))

    assert loader.memory.load(0x1000, 2) == b"\x90\x90"


@pytest.mark.parametrize(
    ("record_type", "entry"),
    (
        (7, 0x12345678),
        (8, 0x123456),
        (9, 0x1234),
    ),
)
def test_srec_termination_record_supplies_the_entry_point(record_type, entry):
    # The start address lives in the address field of the termination record; its data field is empty.
    loader = _load(_record(1, 0x1000, b"\x90"), _record(record_type, entry))

    assert loader.main_object.entry == entry


@pytest.mark.parametrize(
    ("record", "message"),
    (
        (_record(1, 0x1000, b"\x90", byte_count_delta=1), "Data length field does not match"),
        (b"S10410009000", "Invalid checksum"),
        (b"S4041000905B", "Invalid SRec record type"),
        (b"S104100009A5B", "Invalid SRec hexadecimal data"),
        (_record(1, 0x1000, b"\x90\x90") + b" trailing", "Invalid SRec record"),
        (b"", "Invalid SRec record"),
    ),
    ids=("byte-count-too-large", "bad-checksum", "unknown-record-type", "odd-digit-count", "trailing-junk", "empty"),
)
def test_srec_rejects_malformed_records(record, message):
    with pytest.raises(CLEError, match=message):
        cle.SRec.parse_record(record)


def test_srec_load_reports_a_malformed_record():
    with pytest.raises(CLEError, match="Invalid checksum"):
        _load(_record(1, 0x1000, b"\x90"), b"S10410009000")
