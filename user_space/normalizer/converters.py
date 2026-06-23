import datetime
import pwd
import socket
import struct
import time
from typing import Any, Optional

from .constants import UINT32_MAX


def clean_c_string(raw: Any) -> Optional[str]:
    raw_bytes = bytes(raw).split(b"\x00", 1)[0]

    if not raw_bytes:
        return None

    text = raw_bytes.decode("utf-8", errors="ignore")
    text = "".join(ch for ch in text if ch.isprintable()).strip()

    return text or None


def kernel_timestamp_to_iso8601_utc(timestamp_ns: int) -> str:
    if timestamp_ns <= 0:
        epoch_ns = time.time_ns()
    else:
        monotonic_now_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        wall_now_ns = time.time_ns()
        delta_ns = monotonic_now_ns - int(timestamp_ns)

        if delta_ns < 0:
            epoch_ns = wall_now_ns
        else:
            epoch_ns = wall_now_ns - delta_ns

    epoch_ms = epoch_ns // 1_000_000
    seconds, millis = divmod(epoch_ms, 1000)

    dt = datetime.datetime.fromtimestamp(
        seconds,
        tz=datetime.timezone.utc,
    )

    return f"{dt:%Y-%m-%dT%H:%M:%S}.{millis:03d}Z"


def ipv4_from_kernel_u32(value: int) -> Optional[str]:
    if value == 0:
        return None

    try:
        packed = struct.pack("=I", value & UINT32_MAX)
        return socket.inet_ntoa(packed)
    except Exception:
        return None


def normalize_port(port: int) -> Optional[int]:
    port = int(port)
    if 0 < port <= 65535:
        return port
    return None


def uid_to_name(uid: int) -> Optional[str]:
    if uid == UINT32_MAX:
        return "unset"

    try:
        return pwd.getpwuid(int(uid)).pw_name
    except KeyError:
        return None


def build_user_fields(uid: int, auid: int) -> dict:
    user = {
        "id": str(int(uid)),
    }

    username = uid_to_name(uid)
    if username:
        user["name"] = username

    if auid == UINT32_MAX:
        user["audit"] = {
            "id": "-1",
            "name": "unset",
        }
    else:
        audit = {
            "id": str(int(auid)),
        }

        audit_name = uid_to_name(auid)
        if audit_name:
            audit["name"] = audit_name

        user["audit"] = audit

    return user