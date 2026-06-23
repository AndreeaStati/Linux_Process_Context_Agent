import copy

import pytest

from alerting.deduplicator import AlertDeduplicator


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = float(start)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += float(seconds)


def _alert_doc(
    *,
    timestamp="2026-06-19T16:00:00.000Z",
    hostname="ubuntu-1",
    rule_id="lab-network-curl-outbound-http",
    event_category=None,
    event_type=None,
    pid=123,
    ppid=1,
    process_name="curl",
    executable="/usr/bin/curl",
    command_line="curl http://example.com",
    destination_ip="104.20.23.154",
    destination_port=80,
    matched=True,
):
    if event_category is None:
        event_category = ["network"]

    if event_type is None:
        event_type = ["connection"]

    doc = {
        "@timestamp": timestamp,
        "event": {
            "kind": "alert" if matched else "event",
            "category": event_category,
            "type": event_type,
            "action": "network_connection_attempt",
        },
        "host": {
            "hostname": hostname,
        },
        "process": {
            "pid": pid,
            "parent": {
                "pid": ppid,
            },
            "name": process_name,
            "executable": executable,
            "command_line": command_line,
        },
        "edr": {
            "detection": {
                "matched": matched,
                "engine": "sigma_edge",
                "ruleset": "local-sigma",
            }
        },
    }

    if matched:
        doc["edr"]["detection"]["rule_id"] = rule_id
        doc["edr"]["detection"]["rule_title"] = "Test Rule"
        doc["edr"]["detection"]["severity"] = "medium"

    if destination_ip is not None or destination_port is not None:
        doc["destination"] = {}

        if destination_ip is not None:
            doc["destination"]["ip"] = destination_ip

        if destination_port is not None:
            doc["destination"]["port"] = destination_port

    return doc


def test_non_sigma_event_passes_without_dedup_node():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(time_provider=clock)

    doc = _alert_doc(matched=False)

    decision = deduplicator.evaluate(doc)

    assert decision.ecs_doc is doc
    assert decision.drop is False
    assert decision.reason is None
    assert "alert" not in decision.ecs_doc["edr"]
    assert deduplicator.group_count == 0


def test_first_alert_is_marked_as_not_duplicate():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(time_provider=clock)

    doc = _alert_doc()

    decision = deduplicator.evaluate(doc)

    dedup = decision.ecs_doc["edr"]["alert"]["dedup"]

    assert decision.drop is False
    assert dedup["enabled"] is True
    assert dedup["mode"] == "mark"
    assert dedup["is_duplicate"] is False
    assert dedup["count"] == 1
    assert dedup["window_seconds"] == 5.0
    assert dedup["first_seen"] == "2026-06-19T16:00:00.000Z"
    assert dedup["last_seen"] == "2026-06-19T16:00:00.000Z"
    assert dedup["destination_ips"] == ["104.20.23.154"]
    assert dedup["unique_destinations"] == 1
    assert dedup["destination_ports"] == [80]
    assert "reason" not in dedup
    assert deduplicator.group_count == 1


def test_second_same_alert_inside_window_is_marked_as_duplicate():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(time_provider=clock)

    first = _alert_doc(timestamp="2026-06-19T16:00:00.000Z")
    second = _alert_doc(timestamp="2026-06-19T16:00:01.000Z")

    first_decision = deduplicator.evaluate(first)
    second_decision = deduplicator.evaluate(second)

    first_dedup = first_decision.ecs_doc["edr"]["alert"]["dedup"]
    second_dedup = second_decision.ecs_doc["edr"]["alert"]["dedup"]

    assert first_dedup["is_duplicate"] is False

    assert second_decision.drop is False
    assert second_dedup["is_duplicate"] is True
    assert second_dedup["count"] == 2
    assert second_dedup["reason"] == "same_rule_same_process_within_window"
    assert second_dedup["first_seen"] == "2026-06-19T16:00:00.000Z"
    assert second_dedup["last_seen"] == "2026-06-19T16:00:01.000Z"
    assert second_dedup["group_id"] == first_dedup["group_id"]
    assert deduplicator.group_count == 1


def test_network_alerts_to_different_ips_are_grouped_by_default():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(time_provider=clock)

    first = _alert_doc(
        timestamp="2026-06-19T16:00:00.000Z",
        destination_ip="104.20.23.154",
    )
    second = _alert_doc(
        timestamp="2026-06-19T16:00:01.000Z",
        destination_ip="172.66.147.243",
    )

    first_decision = deduplicator.evaluate(first)
    second_decision = deduplicator.evaluate(second)

    first_dedup = first_decision.ecs_doc["edr"]["alert"]["dedup"]
    second_dedup = second_decision.ecs_doc["edr"]["alert"]["dedup"]

    assert second_dedup["is_duplicate"] is True
    assert second_dedup["group_id"] == first_dedup["group_id"]
    assert second_dedup["count"] == 2
    assert second_dedup["destination_ips"] == [
        "104.20.23.154",
        "172.66.147.243",
    ]
    assert second_dedup["unique_destinations"] == 2
    assert second_dedup["destination_ports"] == [80]


def test_include_destination_ip_separates_network_alert_groups():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(
        include_destination_ip=True,
        time_provider=clock,
    )

    first = _alert_doc(
        timestamp="2026-06-19T16:00:00.000Z",
        destination_ip="104.20.23.154",
    )
    second = _alert_doc(
        timestamp="2026-06-19T16:00:01.000Z",
        destination_ip="172.66.147.243",
    )

    first_decision = deduplicator.evaluate(first)
    second_decision = deduplicator.evaluate(second)

    first_dedup = first_decision.ecs_doc["edr"]["alert"]["dedup"]
    second_dedup = second_decision.ecs_doc["edr"]["alert"]["dedup"]

    assert first_dedup["is_duplicate"] is False
    assert second_dedup["is_duplicate"] is False
    assert second_dedup["group_id"] != first_dedup["group_id"]
    assert deduplicator.group_count == 2


def test_alerts_with_different_rule_ids_are_not_duplicates():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(time_provider=clock)

    first = _alert_doc(rule_id="lab-network-curl-outbound-http")
    second = _alert_doc(rule_id="lab-network-outbound-reverse-shell-port")

    first_decision = deduplicator.evaluate(first)
    second_decision = deduplicator.evaluate(second)

    first_dedup = first_decision.ecs_doc["edr"]["alert"]["dedup"]
    second_dedup = second_decision.ecs_doc["edr"]["alert"]["dedup"]

    assert first_dedup["is_duplicate"] is False
    assert second_dedup["is_duplicate"] is False
    assert second_dedup["group_id"] != first_dedup["group_id"]
    assert deduplicator.group_count == 2


def test_duplicate_in_drop_mode_returns_drop_decision():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(
        mode="drop",
        time_provider=clock,
    )

    first = _alert_doc(timestamp="2026-06-19T16:00:00.000Z")
    second = _alert_doc(timestamp="2026-06-19T16:00:01.000Z")

    first_decision = deduplicator.evaluate(first)
    second_decision = deduplicator.evaluate(second)

    first_dedup = first_decision.ecs_doc["edr"]["alert"]["dedup"]
    second_dedup = second_decision.ecs_doc["edr"]["alert"]["dedup"]

    assert first_decision.drop is False
    assert first_dedup["mode"] == "drop"
    assert first_dedup["is_duplicate"] is False

    assert second_decision.drop is True
    assert second_decision.reason == "same_rule_same_process_within_window"
    assert second_dedup["mode"] == "drop"
    assert second_dedup["is_duplicate"] is True


def test_alert_after_window_expiry_starts_new_group():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(
        window_seconds=5.0,
        time_provider=clock,
    )

    first = _alert_doc(timestamp="2026-06-19T16:00:00.000Z")
    first_decision = deduplicator.evaluate(first)
    first_dedup = first_decision.ecs_doc["edr"]["alert"]["dedup"]

    clock.advance(6.0)

    second = _alert_doc(timestamp="2026-06-19T16:00:06.000Z")
    second_decision = deduplicator.evaluate(second)
    second_dedup = second_decision.ecs_doc["edr"]["alert"]["dedup"]

    assert second_dedup["is_duplicate"] is False
    assert second_dedup["count"] == 1
    assert second_dedup["group_id"] == first_dedup["group_id"]
    assert deduplicator.group_count == 1


def test_disabled_deduplicator_passes_document_unchanged():
    clock = FakeClock()
    deduplicator = AlertDeduplicator(
        enabled=False,
        time_provider=clock,
    )

    doc = _alert_doc()
    original = copy.deepcopy(doc)

    decision = deduplicator.evaluate(doc)

    assert decision.ecs_doc == original
    assert decision.drop is False
    assert decision.reason is None
    assert "alert" not in decision.ecs_doc["edr"]
    assert deduplicator.group_count == 0


def test_constructor_rejects_invalid_configuration():
    with pytest.raises(ValueError):
        AlertDeduplicator(window_seconds=0)

    with pytest.raises(ValueError):
        AlertDeduplicator(mode="invalid")

    with pytest.raises(ValueError):
        AlertDeduplicator(max_groups=0)