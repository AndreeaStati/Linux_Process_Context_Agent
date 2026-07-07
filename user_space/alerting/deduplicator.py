from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set


@dataclass
class AlertDedupDecision:

    ecs_doc: Dict[str, Any]
    drop: bool = False
    reason: Optional[str] = None


@dataclass
class _AlertGroup:
    group_id: str
    rule_id: str
    process_pid: Optional[int]
    first_seen: str
    last_seen: str
    expires_at: float
    event_count: int = 1
    destination_ips: Set[str] = field(default_factory=set)
    destination_ports: Set[int] = field(default_factory=set)


class AlertDeduplicator:

    VALID_MODES = {"mark", "drop"}

    def __init__(
        self,
        window_seconds: float = 5.0,
        mode: str = "mark",
        enabled: bool = True,
        include_destination_ip: bool = False,
        max_groups: int = 4096,
        time_provider: Optional[Callable[[], float]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds trebuie sa fie pozitiv")

        if mode not in self.VALID_MODES:
            raise ValueError(f"mode trebuie sa fie unul dintre: {sorted(self.VALID_MODES)}")

        if max_groups <= 0:
            raise ValueError("max_groups trebuie sa fie pozitiv")

        self.window_seconds = float(window_seconds)
        self.mode = mode
        self.enabled = enabled
        self.include_destination_ip = include_destination_ip
        self.max_groups = int(max_groups)
        self._time_provider = time_provider or time.monotonic
        self._groups: Dict[str, _AlertGroup] = {}

    @property
    def group_count(self) -> int:
        return len(self._groups)

    def evaluate(self, ecs_doc: Dict[str, Any]) -> AlertDedupDecision:
        if not self.enabled:
            return AlertDedupDecision(ecs_doc=ecs_doc)

        now = self._time_provider()
        self._cleanup_expired(now)

        if not self._is_sigma_alert(ecs_doc):
            return AlertDedupDecision(ecs_doc=ecs_doc)

        dedup_key = self._build_dedup_key(ecs_doc)
        group_id = self._hash_key(dedup_key)
        timestamp = self._event_timestamp(ecs_doc)

        group = self._groups.get(group_id)
        if group is None:
            group = self._new_group(
                group_id=group_id,
                ecs_doc=ecs_doc,
                timestamp=timestamp,
                now=now,
            )
            self._groups[group_id] = group
            self._enforce_max_groups()
            self._inject_dedup_node(
                ecs_doc=ecs_doc,
                group=group,
                is_duplicate=False,
                reason=None,
            )
            return AlertDedupDecision(ecs_doc=ecs_doc)

        group.event_count += 1
        group.last_seen = timestamp
        group.expires_at = now + self.window_seconds
        self._update_group_destinations(group, ecs_doc)

        reason = "same_rule_same_process_within_window"
        self._inject_dedup_node(
            ecs_doc=ecs_doc,
            group=group,
            is_duplicate=True,
            reason=reason,
        )

        if self.mode == "drop":
            return AlertDedupDecision(
                ecs_doc=ecs_doc,
                drop=True,
                reason=reason,
            )

        return AlertDedupDecision(ecs_doc=ecs_doc)

    def _is_sigma_alert(self, ecs_doc: Dict[str, Any]) -> bool:
        detection = self._get_nested(ecs_doc, ["edr", "detection"])
        return isinstance(detection, dict) and detection.get("matched") is True

    def _new_group(
        self,
        group_id: str,
        ecs_doc: Dict[str, Any],
        timestamp: str,
        now: float,
    ) -> _AlertGroup:
        detection = self._get_nested(ecs_doc, ["edr", "detection"])
        process = ecs_doc.get("process") if isinstance(ecs_doc.get("process"), dict) else {}

        group = _AlertGroup(
            group_id=group_id,
            rule_id=str(detection.get("rule_id", "unknown")) if isinstance(detection, dict) else "unknown",
            process_pid=self._safe_int(process.get("pid")),
            first_seen=timestamp,
            last_seen=timestamp,
            expires_at=now + self.window_seconds,
        )
        self._update_group_destinations(group, ecs_doc)
        return group

    def _build_dedup_key(self, ecs_doc: Dict[str, Any]) -> str:
        host = ecs_doc.get("host") if isinstance(ecs_doc.get("host"), dict) else {}
        process = ecs_doc.get("process") if isinstance(ecs_doc.get("process"), dict) else {}
        destination = ecs_doc.get("destination") if isinstance(ecs_doc.get("destination"), dict) else {}
        event = ecs_doc.get("event") if isinstance(ecs_doc.get("event"), dict) else {}
        detection = self._get_nested(ecs_doc, ["edr", "detection"])
        detection = detection if isinstance(detection, dict) else {}

        category = self._stable_value(event.get("category"))
        event_type = self._stable_value(event.get("type"))
        rule_id = str(detection.get("rule_id", "unknown"))
        pid = str(process.get("pid", ""))
        executable = str(process.get("executable", ""))
        command_line = str(process.get("command_line", ""))
        process_name = str(process.get("name", ""))
        destination_port = str(destination.get("port", ""))

        parts: List[str] = [
            str(host.get("hostname", "")),
            rule_id,
            category,
            event_type,
            pid,
            executable,
            command_line,
            process_name,
            destination_port,
        ]

        if self.include_destination_ip:
            parts.append(str(destination.get("ip", "")))

        return "|".join(parts)

    def _inject_dedup_node(
        self,
        ecs_doc: Dict[str, Any],
        group: _AlertGroup,
        is_duplicate: bool,
        reason: Optional[str],
    ) -> None:
        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"].setdefault("alert", {})

        dedup_node: Dict[str, Any] = {
            "enabled": True,
            "mode": self.mode,
            "is_duplicate": is_duplicate,
            "group_id": group.group_id,
            "window_seconds": self.window_seconds,
            "count": group.event_count,
            "first_seen": group.first_seen,
            "last_seen": group.last_seen,
        }

        if group.destination_ips:
            dedup_node["destination_ips"] = sorted(group.destination_ips)
            dedup_node["unique_destinations"] = len(group.destination_ips)

        if group.destination_ports:
            dedup_node["destination_ports"] = sorted(group.destination_ports)

        if reason:
            dedup_node["reason"] = reason

        ecs_doc["edr"]["alert"]["dedup"] = dedup_node

    def _update_group_destinations(self, group: _AlertGroup, ecs_doc: Dict[str, Any]) -> None:
        destination = ecs_doc.get("destination")
        if not isinstance(destination, dict):
            return

        ip = destination.get("ip")
        if ip:
            group.destination_ips.add(str(ip))

        port = self._safe_int(destination.get("port"))
        if port is not None:
            group.destination_ports.add(port)

    def _cleanup_expired(self, now: float) -> None:
        expired = [
            group_id
            for group_id, group in self._groups.items()
            if group.expires_at <= now
        ]
        for group_id in expired:
            self._groups.pop(group_id, None)

    def _enforce_max_groups(self) -> None:
        if len(self._groups) <= self.max_groups:
            return

        overflow = len(self._groups) - self.max_groups
        oldest_group_ids = sorted(
            self._groups,
            key=lambda group_id: self._groups[group_id].expires_at,
        )[:overflow]
        for group_id in oldest_group_ids:
            self._groups.pop(group_id, None)

    def _event_timestamp(self, ecs_doc: Dict[str, Any]) -> str:
        timestamp = ecs_doc.get("@timestamp")
        if timestamp:
            return str(timestamp)
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def _hash_key(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()

    def _get_nested(self, data: Dict[str, Any], path: List[str]) -> Any:
        current: Any = data
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def _stable_value(self, value: Any) -> str:
        if isinstance(value, list):
            return ",".join(str(item) for item in value)
        return str(value or "")

    def _safe_int(self, value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
