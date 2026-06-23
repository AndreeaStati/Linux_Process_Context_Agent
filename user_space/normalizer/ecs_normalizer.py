import ctypes
import shlex
import socket
import sys
from typing import Any, Dict, Optional

from .constants import (
    ECS_VERSION,
    EVENT_ACCEPT,
    EVENT_CONNECT,
    EVENT_EXECVE,
    EVENT_EXECVEAT,
)
from .converters import (
    build_user_fields,
    clean_c_string,
    ipv4_from_kernel_u32,
    kernel_timestamp_to_iso8601_utc,
    normalize_port,
)
from .kernel_event import KernelEvent, KERNEL_EVENT_SIZE


def prune_empty(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned = {
            key: prune_empty(val)
            for key, val in value.items()
        }

        return {
            key: val
            for key, val in cleaned.items()
            if val is not None and val != "" and val != [] and val != {}
        }

    if isinstance(value, list):
        cleaned = [prune_empty(item) for item in value]
        return [
            item
            for item in cleaned
            if item is not None and item != "" and item != [] and item != {}
        ]

    return value


def get_argv(event: KernelEvent) -> list[str]:
    raw_args = [
        clean_c_string(event.argv0),
        clean_c_string(event.argv1),
        clean_c_string(event.argv2),
        clean_c_string(event.argv3),
        clean_c_string(event.argv4),
        clean_c_string(event.argv5),
    ]

    argv: list[str] = []

    for arg in raw_args:
        if not arg:
            break

        argv.append(arg)

    return argv


class EcsNormalizer:
    def __init__(
        self,
        ecs_version: str = ECS_VERSION,
    ) -> None:
        self.ecs_version = ecs_version
        self.hostname = socket.gethostname()

    def from_ringbuf_sample(self, data: Any, size: int) -> Optional[Dict[str, Any]]:
        if size < KERNEL_EVENT_SIZE:
            print(
                f"[drop] buffer incomplet: {size} < {KERNEL_EVENT_SIZE}",
                file=sys.stderr,
            )
            return None

        raw = ctypes.string_at(data, KERNEL_EVENT_SIZE)
        return self.from_bytes(raw)

    def from_bytes(self, raw: bytes) -> Optional[Dict[str, Any]]:
        if len(raw) < KERNEL_EVENT_SIZE:
            print(
                f"[drop] event_t incomplet: {len(raw)} < {KERNEL_EVENT_SIZE}",
                file=sys.stderr,
            )
            return None

        try:
            event = KernelEvent.from_buffer_copy(raw[:KERNEL_EVENT_SIZE])
        except Exception as exc:
            print(f"[drop] parsare event_t esuata: {exc}", file=sys.stderr)
            return None

        return self.from_kernel_event(event)

    def from_kernel_event(self, event: KernelEvent) -> Optional[Dict[str, Any]]:
        if event.event_type in (EVENT_EXECVE, EVENT_EXECVEAT):
            return self._process_event(event)

        if event.event_type == EVENT_CONNECT:
            return self._network_connect_event(event)

        if event.event_type == EVENT_ACCEPT:
            return self._network_accept_event(event)

        print(
            f"[drop] event_type necunoscut: {event.event_type}",
            file=sys.stderr,
        )
        return None

    def _base_document(self, event: KernelEvent) -> Dict[str, Any]:
        return {
            "@timestamp": kernel_timestamp_to_iso8601_utc(event.timestamp_ns),

            "ecs": {
                "version": self.ecs_version,
            },

            "event": {
                "kind": "event",
                "module": "edr_ebpf",
                "dataset": "edr_ebpf.kernel",
            },

            "host": {
                "hostname": self.hostname,
            },

            "process": {
                "pid": int(event.pid),
                "parent": {
                    "pid": int(event.ppid),
                },
                "name": clean_c_string(event.comm),
            },

            "user": build_user_fields(
                uid=int(event.uid),
                auid=int(event.auid),
            ),
        }

    def _process_event(self, event: KernelEvent) -> Dict[str, Any]:
        doc = self._base_document(event)

        argv = get_argv(event)

        doc["event"].update(
            {
                "category": ["process"],
                "type": ["start"],
                "action": "process_started",
            }
        )

        doc["process"].update(
            {
                "executable": clean_c_string(event.filename),
                "args": argv,
                "args_count": len(argv) if argv else None,
                "command_line": shlex.join(argv) if argv else None,
            }
        )

        return prune_empty(doc)

    def _network_connect_event(self, event: KernelEvent) -> Dict[str, Any]:
        doc = self._base_document(event)

        doc["event"].update(
            {
                "category": ["network"],
                "type": ["connection"],
                "action": "network_connection_attempt",
            }
        )

        doc["network"] = {
            "direction": "outbound",
            "transport": "tcp",
            "type": "ipv4" if int(event.family) == socket.AF_INET else None,
        }

        doc["source"] = {
            "ip": ipv4_from_kernel_u32(event.saddr),
            "port": normalize_port(event.sport),
        }

        doc["destination"] = {
            "ip": ipv4_from_kernel_u32(event.daddr),
            "port": normalize_port(event.dport),
        }

        return prune_empty(doc)

    def _network_accept_event(self, event: KernelEvent) -> Dict[str, Any]:
        doc = self._base_document(event)

        doc["event"].update(
            {
                "category": ["network"],
                "type": ["connection"],
                "action": "network_connection_accepted",
            }
        )

        doc["network"] = {
            "direction": "inbound",
            "transport": "tcp",
            "type": "ipv4" if int(event.family) == socket.AF_INET else None,
        }

        doc["source"] = {
            "ip": ipv4_from_kernel_u32(event.saddr),
            "port": normalize_port(event.sport),
        }

        doc["destination"] = {
            "ip": ipv4_from_kernel_u32(event.daddr),
            "port": normalize_port(event.dport),
        }

        return prune_empty(doc)