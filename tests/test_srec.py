from __future__ import annotations

import io

import pytest

import cle
from cle.errors import CLEError

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


def _record(record_type: int, address: int, data: bytes = b"", *, count_delta: int = 0) -> bytes:
    address_bytes = address.to_bytes(_ADDRESS_BYTES[record_type], "big")
    count = len(address_bytes) + len(data) + 1 + count_delta
    body = bytes([count]) + address_bytes + data
    checksum = (~sum(body)) & 0xFF
    return f"S{record_type}".encode() + body.hex().upper().encode() + f"{checksum:02X}".encode()


def test_srec_loads_one_byte_data_record():
    stream = io.BytesIO(b"\n".join((_record(1, 0x8020, b"\xe9"), _record(9, 0x8020))))

    loader = cle.Loader(stream, auto_load_libs=False, main_opts={"arch": "X86"})

    assert isinstance(loader.main_object, cle.SRec)
    assert loader.main_object.max_addr == 0x8020
    assert loader.main_object.entry == 0x8020
    assert loader.memory.load(0x8020, 1) == b"\xe9"


@pytest.mark.parametrize(
    ("record_type", "entry"),
    (
        (7, 0x12345678),
        (8, 0x123456),
        (9, 0x1234),
    ),
)
def test_srec_start_record_uses_address(record_type, entry):
    stream = io.BytesIO(b"\n".join((_record(1, 0x1000, b"\x90"), _record(record_type, entry))))

    loader = cle.Loader(stream, auto_load_libs=False, main_opts={"arch": "X86"})

    assert loader.main_object.entry == entry


@pytest.mark.parametrize(
    "record",
    (
        _record(1, 0x1000, b"\x90", count_delta=1),
        b"S10410009000",
        b"S4041000905B",
        _record(1, 0x1000, b"\x90") + b"00",
        b"S104100009A5B",
    ),
)
def test_srec_rejects_malformed_records(record):
    with pytest.raises(CLEError):
        cle.SRec.parse_record(record)
