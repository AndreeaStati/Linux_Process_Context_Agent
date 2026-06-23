from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Set


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    name: str
    severity: str
    required_rule_ids: Set[str]
    summary: str


@dataclass
class CorrelationObservation:
    event_key: str
    seen_at: float
    timestamp: str | None
    rule_id: str | None
    rule_title: str | None
    event_category: list[Any]
    event_type: list[Any]
    host: str | None
    user_id: str | None
    process_pid: Any
    process_ppid: Any
    process_name: str | None
    process_executable: str | None
    process_command_line: str | None
    destination_ip: str | None
    destination_port: Any

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_key": self.event_key,
            "seen_at": self.seen_at,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "event_category": self.event_category,
            "event_type": self.event_type,
            "host": self.host,
            "user_id": self.user_id,
            "process_pid": self.process_pid,
            "process_ppid": self.process_ppid,
            "process_name": self.process_name,
            "process_executable": self.process_executable,
            "process_command_line": self.process_command_line,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
        }