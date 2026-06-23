import re
import socket
import struct

from normalizer.constants import UINT32_MAX
from normalizer.converters import (
    build_user_fields,
    clean_c_string,
    ipv4_from_kernel_u32,
    kernel_timestamp_to_iso8601_utc,
    normalize_port,
)


def kernel_u32_from_ipv4(ip: str) -> int:
    return struct.unpack("=I", socket.inet_aton(ip))[0]


def test_clean_c_string_removes_null_termination():
    raw = b"bash\x00garbage"
    assert clean_c_string(raw) == "bash"


def test_clean_c_string_returns_none_for_empty_string():
    raw = b"\x00\x00\x00"
    assert clean_c_string(raw) is None


def test_ipv4_from_kernel_u32():
    value = kernel_u32_from_ipv4("8.8.8.8")
    assert ipv4_from_kernel_u32(value) == "8.8.8.8"


def test_ipv4_from_zero_is_none():
    assert ipv4_from_kernel_u32(0) is None


def test_normalize_valid_port():
    assert normalize_port(80) == 80
    assert normalize_port(65535) == 65535


def test_normalize_invalid_port():
    assert normalize_port(0) is None
    assert normalize_port(70000) is None


def test_unset_auid_is_mapped_correctly():
    user = build_user_fields(uid=0, auid=UINT32_MAX)

    assert user["id"] == "0"
    assert user["name"] == "root"
    assert user["audit"]["id"] == "-1"
    assert user["audit"]["name"] == "unset"


def test_kernel_timestamp_to_iso8601_utc_format():
    timestamp = kernel_timestamp_to_iso8601_utc(0)

    assert re.match(
        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$",
        timestamp,
    )