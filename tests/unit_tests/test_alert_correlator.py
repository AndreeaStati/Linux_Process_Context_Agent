from alerting.correlator import AlertCorrelator


def _base_alert_doc(
    *,
    timestamp,
    rule_id,
    rule_title="Test Rule",
    severity="medium",
    hostname="ubuntu-1",
    event_category=None,
    event_type=None,
    event_action="process_started",
    pid=123,
    ppid=1,
    process_name="curl",
    executable="/usr/bin/curl",
    command_line="curl http://example.com",
    destination_ip=None,
    destination_port=None,
    matched=True,
    is_duplicate=False,
):
    if event_category is None:
        event_category = ["process"]

    if event_type is None:
        event_type = ["start"]

    doc = {
        "@timestamp": timestamp,
        "event": {
            "kind": "alert" if matched else "event",
            "module": "edr_ebpf",
            "dataset": "edr_ebpf.kernel",
            "category": event_category,
            "type": event_type,
            "action": event_action,
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
        "user": {
            "id": "1000",
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
        doc["edr"]["detection"].update(
            {
                "rule_id": rule_id,
                "rule_title": rule_title,
                "severity": severity,
                "matches": [
                    {
                        "rule_id": rule_id,
                        "rule_title": rule_title,
                        "level": severity,
                    }
                ],
            }
        )
        doc["rule"] = {
            "id": rule_id,
            "name": rule_title,
            "level": severity,
            "ruleset": "local-sigma",
        }

    if destination_ip is not None or destination_port is not None:
        doc["destination"] = {}

        if destination_ip is not None:
            doc["destination"]["ip"] = destination_ip

        if destination_port is not None:
            doc["destination"]["port"] = destination_port

    if is_duplicate:
        doc["edr"].setdefault("alert", {})
        doc["edr"]["alert"]["dedup"] = {
            "enabled": True,
            "mode": "mark",
            "is_duplicate": True,
            "group_id": "duplicate-group",
            "count": 2,
            "reason": "same_rule_same_process_within_window",
        }

    return doc


def _curl_process_alert(
    *,
    timestamp="2026-06-19T16:00:00.000Z",
    pid=123,
    ppid=1,
    command_line="curl http://example.com",
    is_duplicate=False,
):
    return _base_alert_doc(
        timestamp=timestamp,
        rule_id="lab-process-curl-wget-external-url",
        rule_title="Curl Or Wget External URL Execution",
        severity="medium",
        event_category=["process"],
        event_type=["start"],
        event_action="process_started",
        pid=pid,
        ppid=ppid,
        process_name="curl",
        executable="/usr/bin/curl",
        command_line=command_line,
        is_duplicate=is_duplicate,
    )


def _curl_network_alert(
    *,
    timestamp="2026-06-19T16:00:01.000Z",
    pid=123,
    ppid=1,
    command_line="curl http://example.com",
    destination_ip="104.20.23.154",
    destination_port=80,
    is_duplicate=False,
):
    return _base_alert_doc(
        timestamp=timestamp,
        rule_id="lab-network-curl-outbound-http",
        rule_title="Curl Outbound HTTP Connection",
        severity="medium",
        event_category=["network"],
        event_type=["connection"],
        event_action="network_connection_attempt",
        pid=pid,
        ppid=ppid,
        process_name="curl",
        executable="/usr/bin/curl",
        command_line=command_line,
        destination_ip=destination_ip,
        destination_port=destination_port,
        is_duplicate=is_duplicate,
    )


def _shell_inline_alert(
    *,
    timestamp="2026-06-19T16:00:00.000Z",
    pid=123,
    ppid=1,
    command_line="bash -c curl http://example.com",
):
    return _base_alert_doc(
        timestamp=timestamp,
        rule_id="lab-process-shell-inline-command",
        rule_title="Shell Inline Command Execution",
        severity="low",
        event_category=["process"],
        event_type=["start"],
        event_action="process_started",
        pid=pid,
        ppid=ppid,
        process_name="bash",
        executable="/usr/bin/bash",
        command_line=command_line,
    )


def _tmp_execution_alert(
    *,
    timestamp="2026-06-19T16:00:00.000Z",
    pid=500,
    ppid=1,
    command_line="/tmp/edr_sleep 10",
):
    return _base_alert_doc(
        timestamp=timestamp,
        rule_id="lab-process-execution-from-writable-tmp",
        rule_title="Execution From World Writable Temporary Directory",
        severity="high",
        event_category=["process"],
        event_type=["start"],
        event_action="process_started",
        pid=pid,
        ppid=ppid,
        process_name="edr_sleep",
        executable="/tmp/edr_sleep",
        command_line=command_line,
    )


def _reverse_shell_port_alert(
    *,
    timestamp="2026-06-19T16:00:01.000Z",
    pid=500,
    ppid=1,
    process_name="edr_sleep",
    executable="/tmp/edr_sleep",
    command_line="/tmp/edr_sleep 10",
    destination_ip="127.0.0.1",
    destination_port=4444,
):
    return _base_alert_doc(
        timestamp=timestamp,
        rule_id="lab-network-outbound-reverse-shell-port",
        rule_title="Outbound Connection To Common Reverse Shell Port",
        severity="high",
        event_category=["network"],
        event_type=["connection"],
        event_action="network_connection_attempt",
        pid=pid,
        ppid=ppid,
        process_name=process_name,
        executable=executable,
        command_line=command_line,
        destination_ip=destination_ip,
        destination_port=destination_port,
    )


def test_non_sigma_event_passes_without_correlation():
    correlator = AlertCorrelator()

    doc = _base_alert_doc(
        timestamp="2026-06-19T16:00:00.000Z",
        rule_id="lab-process-curl-wget-external-url",
        matched=False,
    )

    result = correlator.process(doc)

    assert result is doc
    assert "correlation" not in result["edr"]


def test_single_sigma_alert_does_not_create_correlation():
    correlator = AlertCorrelator()

    doc = _curl_process_alert()

    result = correlator.process(doc)

    assert result is doc
    assert "correlation" not in result["edr"]


def test_curl_process_and_network_alert_create_external_transfer_correlation():
    correlator = AlertCorrelator()

    process_doc = _curl_process_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=123,
    )
    network_doc = _curl_network_alert(
        timestamp="2026-06-19T16:00:01.000Z",
        pid=123,
        destination_ip="104.20.23.154",
        destination_port=80,
    )

    process_result = correlator.process(process_doc)
    network_result = correlator.process(network_doc)

    assert "correlation" not in process_result["edr"]

    correlation = network_result["edr"]["correlation"]

    assert correlation["matched"] is True
    assert correlation["engine"] == "edge_correlator"
    assert correlation["rule_id"] == "corr-external-transfer-outbound-http"
    assert correlation["name"] == "External Transfer Followed By Outbound HTTP"
    assert correlation["severity"] == "high"
    assert correlation["window_seconds"] == 60.0
    assert correlation["event_count"] == 2
    assert correlation["related_rules"] == [
        "lab-network-curl-outbound-http",
        "lab-process-curl-wget-external-url",
    ]
    assert correlation["first_seen"] == "2026-06-19T16:00:00.000Z"
    assert correlation["last_seen"] == "2026-06-19T16:00:01.000Z"
    assert correlation["related_processes"] == [
        {
            "pid": 123,
            "ppid": 1,
            "name": "curl",
            "executable": "/usr/bin/curl",
            "command_line": "curl http://example.com",
        }
    ]
    assert correlation["related_destinations"] == [
        {
            "ip": "104.20.23.154",
            "port": 80,
        }
    ]


def test_shell_inline_and_curl_process_create_shell_external_transfer_correlation():
    correlator = AlertCorrelator()

    shell_doc = _shell_inline_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=321,
    )
    curl_doc = _curl_process_alert(
        timestamp="2026-06-19T16:00:00.100Z",
        pid=321,
    )

    shell_result = correlator.process(shell_doc)
    curl_result = correlator.process(curl_doc)

    assert "correlation" not in shell_result["edr"]

    correlation = curl_result["edr"]["correlation"]

    assert correlation["matched"] is True
    assert correlation["rule_id"] == "corr-shell-inline-external-transfer"
    assert correlation["name"] == "Shell Inline Command With External Transfer Tool"
    assert correlation["severity"] == "high"
    assert correlation["event_count"] == 2
    assert correlation["related_rules"] == [
        "lab-process-curl-wget-external-url",
        "lab-process-shell-inline-command",
    ]


def test_shell_inline_and_network_create_shell_network_activity_correlation():
    correlator = AlertCorrelator()

    shell_doc = _shell_inline_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=321,
    )
    network_doc = _curl_network_alert(
        timestamp="2026-06-19T16:00:00.200Z",
        pid=321,
    )

    shell_result = correlator.process(shell_doc)
    network_result = correlator.process(network_doc)

    assert "correlation" not in shell_result["edr"]

    correlation = network_result["edr"]["correlation"]

    assert correlation["matched"] is True
    assert correlation["rule_id"] == "corr-shell-inline-network-activity"
    assert correlation["name"] == "Shell Inline Command With Network Activity"
    assert correlation["severity"] == "high"
    assert correlation["related_rules"] == [
        "lab-network-curl-outbound-http",
        "lab-process-shell-inline-command",
    ]


def test_duplicate_alert_is_ignored_by_default():
    correlator = AlertCorrelator(ignore_duplicates=True)

    process_doc = _curl_process_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=123,
    )
    duplicate_network_doc = _curl_network_alert(
        timestamp="2026-06-19T16:00:01.000Z",
        pid=123,
        is_duplicate=True,
    )

    correlator.process(process_doc)
    result = correlator.process(duplicate_network_doc)

    assert "correlation" not in result["edr"]


def test_duplicate_alert_can_be_processed_when_ignore_duplicates_is_false():
    correlator = AlertCorrelator(ignore_duplicates=False)

    process_doc = _curl_process_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=123,
    )
    duplicate_network_doc = _curl_network_alert(
        timestamp="2026-06-19T16:00:01.000Z",
        pid=123,
        is_duplicate=True,
    )

    correlator.process(process_doc)
    result = correlator.process(duplicate_network_doc)

    assert result["edr"]["correlation"]["matched"] is True
    assert (
        result["edr"]["correlation"]["rule_id"]
        == "corr-external-transfer-outbound-http"
    )


def test_tmp_execution_and_reverse_shell_same_process_create_critical_correlation():
    correlator = AlertCorrelator()

    tmp_doc = _tmp_execution_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=500,
        command_line="/tmp/evil 10",
    )
    network_doc = _reverse_shell_port_alert(
        timestamp="2026-06-19T16:00:01.000Z",
        pid=500,
        process_name="evil",
        executable="/tmp/evil",
        command_line="/tmp/evil 10",
        destination_ip="127.0.0.1",
        destination_port=4444,
    )

    tmp_result = correlator.process(tmp_doc)
    network_result = correlator.process(network_doc)

    assert "correlation" not in tmp_result["edr"]

    correlation = network_result["edr"]["correlation"]

    assert correlation["matched"] is True
    assert correlation["rule_id"] == "corr-temp-exec-reverse-shell-port"
    assert correlation["name"] == "Temporary Directory Execution With Reverse Shell Port"
    assert correlation["severity"] == "critical"
    assert correlation["event_count"] == 2
    assert correlation["related_rules"] == [
        "lab-network-outbound-reverse-shell-port",
        "lab-process-execution-from-writable-tmp",
    ]
    assert correlation["related_destinations"] == [
        {
            "ip": "127.0.0.1",
            "port": 4444,
        }
    ]


def test_tmp_execution_and_reverse_shell_different_processes_are_not_correlated():
    correlator = AlertCorrelator()

    tmp_doc = _tmp_execution_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=500,
        ppid=777,
        command_line="/tmp/edr_sleep 10",
    )
    network_doc = _reverse_shell_port_alert(
        timestamp="2026-06-19T16:00:01.000Z",
        pid=600,
        ppid=777,
        process_name="python3.10",
        executable="/usr/bin/python3.10",
        command_line="python3 -",
        destination_ip="127.0.0.1",
        destination_port=4444,
    )

    correlator.process(tmp_doc)
    result = correlator.process(network_doc)

    assert "correlation" not in result["edr"]


def test_same_executable_with_different_pid_and_command_line_is_not_correlated():
    correlator = AlertCorrelator()

    first_curl_process = _curl_process_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=100,
        command_line="curl http://example.com",
    )
    second_curl_network = _curl_network_alert(
        timestamp="2026-06-19T16:00:01.000Z",
        pid=200,
        command_line="curl http://different.example",
        destination_ip="104.20.23.154",
        destination_port=80,
    )

    correlator.process(first_curl_process)
    result = correlator.process(second_curl_network)

    assert "correlation" not in result["edr"]


def test_old_observations_are_removed_after_window_expires(monkeypatch):
    fake_now = {"value": 1000.0}

    def fake_time():
        return fake_now["value"]

    monkeypatch.setattr("alerting.correlator.time.time", fake_time)

    correlator = AlertCorrelator(window_seconds=5.0)

    process_doc = _curl_process_alert(
        timestamp="2026-06-19T16:00:00.000Z",
        pid=123,
    )
    network_doc = _curl_network_alert(
        timestamp="2026-06-19T16:00:10.000Z",
        pid=123,
    )

    correlator.process(process_doc)

    fake_now["value"] = 1006.0

    result = correlator.process(network_doc)

    assert "correlation" not in result["edr"]


def test_non_dict_input_is_returned_unchanged():
    correlator = AlertCorrelator()

    value = "not-a-dict"

    result = correlator.process(value)

    assert result == value