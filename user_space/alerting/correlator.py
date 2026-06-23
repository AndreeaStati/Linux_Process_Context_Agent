from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, Iterable, List, Optional, Set

from .correlation_models import CorrelationObservation, CorrelationRule
from .correlation_rules import DEFAULT_CORRELATION_RULES


class AlertCorrelator:

    def __init__(
        self,
        window_seconds: float = 60.0,
        ignore_duplicates: bool = True,
        max_events_per_scope: int = 128,
        rules: Optional[List[CorrelationRule]] = None,
    ) -> None:
        self.window_seconds = float(window_seconds)
        self.ignore_duplicates = bool(ignore_duplicates)
        self.max_events_per_scope = int(max_events_per_scope)
        self.rules = rules if rules is not None else list(DEFAULT_CORRELATION_RULES)

        self._cache: Dict[str, List[CorrelationObservation]] = {}

    def process(self, ecs_doc: Dict[str, Any]) -> Dict[str, Any]:

        if not isinstance(ecs_doc, dict):
            return ecs_doc

        now = time.time()
        self._cleanup(now)

        if not self._is_sigma_alert(ecs_doc):
            return ecs_doc

        if self.ignore_duplicates and self._is_duplicate_alert(ecs_doc):
            return ecs_doc

        observation = self._build_observation(ecs_doc, now)

        if not observation.rule_id:
            return ecs_doc

        scopes = self._build_scopes(ecs_doc)

        related_observations = self._collect_related_observations(scopes)
        related_observations.append(observation)
        related_observations = self._deduplicate_observations(related_observations)

        correlation_matches = self._evaluate_rules(related_observations)

        if correlation_matches:
            self._inject_correlation(
                ecs_doc=ecs_doc,
                current_observation=observation,
                related_observations=related_observations,
                matches=correlation_matches,
            )

        self._remember(scopes, observation)

        return ecs_doc

    def _is_sigma_alert(self, ecs_doc: Dict[str, Any]) -> bool:
        return self._get(ecs_doc, "edr.detection.matched") is True

    def _is_duplicate_alert(self, ecs_doc: Dict[str, Any]) -> bool:
        return self._get(ecs_doc, "edr.alert.dedup.is_duplicate") is True

    def _build_observation(
        self,
        ecs_doc: Dict[str, Any],
        now: float,
    ) -> CorrelationObservation:
        rule_id = self._get(ecs_doc, "edr.detection.rule_id") or self._get(
            ecs_doc,
            "rule.id",
        )
        rule_title = self._get(ecs_doc, "edr.detection.rule_title") or self._get(
            ecs_doc,
            "rule.name",
        )

        event_category = self._as_list(self._get(ecs_doc, "event.category"))
        event_type = self._as_list(self._get(ecs_doc, "event.type"))

        process_pid = self._get(ecs_doc, "process.pid")
        process_ppid = self._get(ecs_doc, "process.parent.pid")
        process_name = self._get(ecs_doc, "process.name")
        process_executable = self._get(ecs_doc, "process.executable")
        process_command_line = self._get(ecs_doc, "process.command_line")

        destination_ip = self._get(ecs_doc, "destination.ip")
        destination_port = self._get(ecs_doc, "destination.port")

        timestamp = ecs_doc.get("@timestamp")
        host = self._get(ecs_doc, "host.hostname")
        user_id = self._get(ecs_doc, "user.id")

        event_key_material = "|".join(
            str(value)
            for value in [
                timestamp,
                rule_id,
                process_pid,
                process_ppid,
                process_name,
                process_executable,
                process_command_line,
                destination_ip,
                destination_port,
            ]
        )

        event_key = hashlib.sha256(event_key_material.encode("utf-8")).hexdigest()

        return CorrelationObservation(
            event_key=event_key,
            seen_at=now,
            timestamp=str(timestamp) if timestamp is not None else None,
            rule_id=str(rule_id) if rule_id is not None else None,
            rule_title=str(rule_title) if rule_title is not None else None,
            event_category=event_category,
            event_type=event_type,
            host=str(host) if host is not None else None,
            user_id=str(user_id) if user_id is not None else None,
            process_pid=process_pid,
            process_ppid=process_ppid,
            process_name=str(process_name) if process_name is not None else None,
            process_executable=str(process_executable)
            if process_executable is not None
            else None,
            process_command_line=str(process_command_line)
            if process_command_line is not None
            else None,
            destination_ip=str(destination_ip) if destination_ip is not None else None,
            destination_port=destination_port,
        )

    def _build_scopes(self, ecs_doc: Dict[str, Any]) -> Set[str]:

        host = self._get(ecs_doc, "host.hostname") or "unknown-host"
        pid = self._get(ecs_doc, "process.pid")
        command_line = self._get(ecs_doc, "process.command_line")

        scopes: Set[str] = set()

        if pid is not None:
            scopes.add(f"host:{host}:pid:{pid}")

        if command_line:
            command_hash = hashlib.sha256(
                str(command_line).encode("utf-8")
            ).hexdigest()
            scopes.add(f"host:{host}:cmd:{command_hash}")

        return scopes

    def _collect_related_observations(
        self,
        scopes: Iterable[str],
    ) -> List[CorrelationObservation]:
        observations: List[CorrelationObservation] = []

        for scope in scopes:
            observations.extend(self._cache.get(scope, []))

        return observations

    def _deduplicate_observations(
        self,
        observations: List[CorrelationObservation],
    ) -> List[CorrelationObservation]:
        seen: Set[str] = set()
        result: List[CorrelationObservation] = []

        for observation in observations:
            if observation.event_key in seen:
                continue

            seen.add(observation.event_key)
            result.append(observation)

        return result

    def _evaluate_rules(
        self,
        observations: List[CorrelationObservation],
    ) -> List[CorrelationRule]:
        observed_rule_ids = {
            observation.rule_id
            for observation in observations
            if observation.rule_id is not None
        }

        matches: List[CorrelationRule] = []

        for rule in self.rules:
            if rule.required_rule_ids.issubset(observed_rule_ids):
                matches.append(rule)

        return matches

    def _inject_correlation(
        self,
        ecs_doc: Dict[str, Any],
        current_observation: CorrelationObservation,
        related_observations: List[CorrelationObservation],
        matches: List[CorrelationRule],
    ) -> None:
        primary_match = self._highest_severity_match(matches)

        related_rule_ids = sorted(
            {
                observation.rule_id
                for observation in related_observations
                if observation.rule_id is not None
            }
        )

        related_processes = self._build_related_processes(related_observations)
        related_destinations = self._build_related_destinations(related_observations)

        first_seen = self._first_timestamp(related_observations)
        last_seen = self._last_timestamp(related_observations)

        correlation_id = self._build_correlation_id(
            primary_match=primary_match,
            current_observation=current_observation,
            related_rule_ids=related_rule_ids,
        )

        edr = ecs_doc.setdefault("edr", {})

        edr["correlation"] = {
            "matched": True,
            "engine": "edge_correlator",
            "correlation_id": correlation_id,
            "rule_id": primary_match.rule_id,
            "name": primary_match.name,
            "severity": primary_match.severity,
            "summary": primary_match.summary,
            "window_seconds": self.window_seconds,
            "event_count": len(related_observations),
            "related_rules": related_rule_ids,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "related_processes": related_processes,
            "related_destinations": related_destinations,
        }

    def _remember(
        self,
        scopes: Iterable[str],
        observation: CorrelationObservation,
    ) -> None:
        for scope in scopes:
            bucket = self._cache.setdefault(scope, [])

            already_seen = any(
                existing.event_key == observation.event_key
                for existing in bucket
            )

            if not already_seen:
                bucket.append(observation)

            if len(bucket) > self.max_events_per_scope:
                del bucket[: len(bucket) - self.max_events_per_scope]

    def _cleanup(self, now: float) -> None:
        cutoff = now - self.window_seconds
        empty_scopes: List[str] = []

        for scope, observations in self._cache.items():
            self._cache[scope] = [
                observation
                for observation in observations
                if observation.seen_at >= cutoff
            ]

            if not self._cache[scope]:
                empty_scopes.append(scope)

        for scope in empty_scopes:
            self._cache.pop(scope, None)

    def _highest_severity_match(
        self,
        matches: List[CorrelationRule],
    ) -> CorrelationRule:
        severity_rank = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        return max(
            matches,
            key=lambda rule: severity_rank.get(rule.severity.lower(), 0),
        )

    def _build_correlation_id(
        self,
        primary_match: CorrelationRule,
        current_observation: CorrelationObservation,
        related_rule_ids: List[str],
    ) -> str:
        material = "|".join(
            str(value)
            for value in [
                primary_match.rule_id,
                current_observation.host,
                current_observation.process_pid,
                current_observation.process_ppid,
                current_observation.process_command_line,
                ",".join(related_rule_ids),
            ]
        )

        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _build_related_processes(
        self,
        observations: List[CorrelationObservation],
    ) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        processes: List[Dict[str, Any]] = []

        for observation in observations:
            material = "|".join(
                str(value)
                for value in [
                    observation.process_pid,
                    observation.process_ppid,
                    observation.process_name,
                    observation.process_executable,
                    observation.process_command_line,
                ]
            )

            if material in seen:
                continue

            seen.add(material)

            processes.append(
                {
                    "pid": observation.process_pid,
                    "ppid": observation.process_ppid,
                    "name": observation.process_name,
                    "executable": observation.process_executable,
                    "command_line": observation.process_command_line,
                }
            )

        return processes

    def _build_related_destinations(
        self,
        observations: List[CorrelationObservation],
    ) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        destinations: List[Dict[str, Any]] = []

        for observation in observations:
            ip = observation.destination_ip
            port = observation.destination_port

            if ip is None and port is None:
                continue

            material = f"{ip}:{port}"

            if material in seen:
                continue

            seen.add(material)

            destinations.append(
                {
                    "ip": ip,
                    "port": port,
                }
            )

        return destinations

    def _first_timestamp(
        self,
        observations: List[CorrelationObservation],
    ) -> Optional[str]:
        timestamps = [
            observation.timestamp
            for observation in observations
            if observation.timestamp
        ]

        if not timestamps:
            return None

        return min(timestamps)

    def _last_timestamp(
        self,
        observations: List[CorrelationObservation],
    ) -> Optional[str]:
        timestamps = [
            observation.timestamp
            for observation in observations
            if observation.timestamp
        ]

        if not timestamps:
            return None

        return max(timestamps)

    def _get(
        self,
        obj: Dict[str, Any],
        dotted_path: str,
        default: Any = None,
    ) -> Any:
        current: Any = obj

        for part in dotted_path.split("."):
            if not isinstance(current, dict):
                return default

            if part not in current:
                return default

            current = current[part]

        return current

    def _as_list(self, value: Any) -> List[Any]:
        if value is None:
            return []

        if isinstance(value, list):
            return value

        return [value]