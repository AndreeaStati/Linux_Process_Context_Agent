import socket
import struct
import ctypes

from normalizer.constants import (
    EVENT_ACCEPT,
    EVENT_CONNECT,
    EVENT_EXECVE,
    UINT32_MAX,
)
from normalizer.ecs_normalizer import EcsNormalizer
from normalizer.kernel_event import KernelEvent
from normalizer.kernel_event import KERNEL_EVENT_SIZE


def kernel_u32_from_ipv4(ip: str) -> int:
    return struct.unpack("=I", socket.inet_aton(ip))[0]


def make_base_event() -> KernelEvent:
    event = KernelEvent()

    event.timestamp_ns = 0
    event.pid = 1234
    event.ppid = 1000
    event.uid = 0
    event.auid = UINT32_MAX
    event.comm = b"bash"

    return event


def test_execve_event_is_normalized_to_ecs_process_start():
    event = make_base_event()

    event.event_type = EVENT_EXECVE
    event.filename = b"/usr/bin/bash"
    event.argv0 = b"bash"
    event.argv1 = b"-c"
    event.argv2 = b"id"

    normalizer = EcsNormalizer()
    doc = normalizer.from_kernel_event(event)

    assert doc is not None

    assert doc["ecs"]["version"] == "8.11.0"

    assert doc["event"]["category"] == ["process"]
    assert doc["event"]["type"] == ["start"]
    assert doc["event"]["action"] == "process_started"

    assert doc["process"]["pid"] == 1234
    assert doc["process"]["parent"]["pid"] == 1000
    assert doc["process"]["name"] == "bash"
    assert doc["process"]["executable"] == "/usr/bin/bash"

    assert doc["process"]["args"] == ["bash", "-c", "id"]
    assert doc["process"]["args_count"] == 3
    assert doc["process"]["command_line"] == "bash -c id"

    assert doc["user"]["id"] == "0"
    assert doc["user"]["name"] == "root"
    assert doc["user"]["audit"]["id"] == "-1"
    assert doc["user"]["audit"]["name"] == "unset"


def test_connect_event_is_normalized_to_ecs_outbound_network():
    event = make_base_event()

    event.event_type = EVENT_CONNECT
    event.comm = b"curl"
    event.family = socket.AF_INET
    event.daddr = kernel_u32_from_ipv4("8.8.8.8")
    event.dport = 53

    normalizer = EcsNormalizer()
    doc = normalizer.from_kernel_event(event)

    assert doc is not None

    assert doc["event"]["category"] == ["network"]
    assert doc["event"]["type"] == ["connection"]
    assert doc["event"]["action"] == "network_connection_attempt"

    assert doc["network"]["direction"] == "outbound"
    assert doc["network"]["transport"] == "tcp"
    assert doc["network"]["type"] == "ipv4"

    assert doc["process"]["name"] == "curl"

    assert doc["destination"]["ip"] == "8.8.8.8"
    assert doc["destination"]["port"] == 53

    assert "source" not in doc


def test_accept_event_is_normalized_to_ecs_inbound_network():
    event = make_base_event()

    event.event_type = EVENT_ACCEPT
    event.comm = b"python3"
    event.family = socket.AF_INET
    event.saddr = kernel_u32_from_ipv4("127.0.0.1")
    event.sport = 43122

    normalizer = EcsNormalizer()
    doc = normalizer.from_kernel_event(event)

    assert doc is not None

    assert doc["event"]["category"] == ["network"]
    assert doc["event"]["type"] == ["connection"]
    assert doc["event"]["action"] == "network_connection_accepted"

    assert doc["network"]["direction"] == "inbound"
    assert doc["network"]["transport"] == "tcp"
    assert doc["network"]["type"] == "ipv4"

    assert doc["source"]["ip"] == "127.0.0.1"
    assert doc["source"]["port"] == 43122

    assert "destination" not in doc


def test_normalizer_accepts_raw_kernel_event_bytes():
    event = make_base_event()

    event.event_type = EVENT_EXECVE
    event.filename = b"/bin/true"
    event.argv0 = b"/bin/true"

    raw = bytes(event)

    assert len(raw) == KERNEL_EVENT_SIZE

    normalizer = EcsNormalizer()
    doc = normalizer.from_bytes(raw)

    assert doc is not None
    assert doc["process"]["executable"] == "/bin/true"
    assert doc["process"]["args"] == ["/bin/true"]
    assert doc["event"]["action"] == "process_started"


def test_normalizer_drops_incomplete_raw_event():
    normalizer = EcsNormalizer()

    raw = b"\x00" * 100
    doc = normalizer.from_bytes(raw)

    assert doc is None