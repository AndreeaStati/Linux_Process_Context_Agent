from pathlib import Path

from detection.sigma_engine import SigmaEngine


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = PROJECT_ROOT / "rules"


def test_sigma_engine_loads_local_rules():
    engine = SigmaEngine(RULES_DIR)

    assert len(engine.rules) >= 6
    assert {rule.rule_id for rule in engine.rules} >= {
        "lab-process-curl-wget-external-url",
        "lab-process-sensitive-account-file-read",
        "lab-network-outbound-reverse-shell-port",
        "lab-network-curl-outbound-http",
    }


def test_sigma_engine_marks_curl_external_url_as_alert():
    engine = SigmaEngine(RULES_DIR)
    doc = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
        },
        "process": {
            "pid": 123,
            "name": "curl",
            "executable": "/usr/bin/curl",
            "command_line": "curl http://example.com",
            "args": ["curl", "http://example.com"],
        },
    }

    result = engine.evaluate(doc)

    assert result["event"]["kind"] == "alert"
    assert result["rule"]["id"] == "lab-process-curl-wget-external-url"
    assert result["edr"]["detection"]["matched"] is True
    assert result["edr"]["detection"]["engine"] == "sigma_edge"
    assert result["edr"]["detection"]["severity"] == "medium"


def test_sigma_engine_does_not_mark_benign_true_execution():
    engine = SigmaEngine(RULES_DIR)
    doc = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
        },
        "process": {
            "pid": 124,
            "name": "true",
            "executable": "/usr/bin/true",
            "command_line": "/usr/bin/true",
            "args": ["/usr/bin/true"],
        },
    }

    result = engine.evaluate(doc)

    assert result["event"]["kind"] == "event"
    assert "rule" not in result
    assert result["edr"]["detection"]["matched"] is False


def test_sigma_engine_marks_sensitive_file_read():
    engine = SigmaEngine(RULES_DIR)
    doc = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
        },
        "process": {
            "pid": 125,
            "name": "cat",
            "executable": "/usr/bin/cat",
            "command_line": "cat /etc/passwd",
            "args": ["cat", "/etc/passwd"],
        },
    }

    result = engine.evaluate(doc)

    assert result["event"]["kind"] == "alert"
    assert result["rule"]["id"] == "lab-process-sensitive-account-file-read"
    assert result["edr"]["detection"]["matched"] is True


def test_sigma_engine_marks_outbound_reverse_shell_port():
    engine = SigmaEngine(RULES_DIR)
    doc = {
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "network_connection_attempt",
        },
        "network": {
            "direction": "outbound",
            "transport": "tcp",
            "type": "ipv4",
        },
        "process": {
            "pid": 126,
            "name": "bash",
        },
        "destination": {
            "ip": "10.10.10.10",
            "port": 4444,
        },
    }

    result = engine.evaluate(doc)

    assert result["event"]["kind"] == "alert"
    assert result["rule"]["id"] == "lab-network-outbound-reverse-shell-port"
    assert result["edr"]["detection"]["matched"] is True


def test_sigma_engine_supports_inline_shell_args_list_matching():
    engine = SigmaEngine(RULES_DIR)
    doc = {
        "event": {
            "kind": "event",
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
        },
        "process": {
            "pid": 127,
            "name": "bash",
            "executable": "/usr/bin/bash",
            "command_line": "bash -c id",
            "args": ["bash", "-c", "id"],
        },
    }

    result = engine.evaluate(doc)

    assert result["event"]["kind"] == "alert"
    assert result["rule"]["id"] == "lab-process-shell-inline-command"
    assert result["edr"]["detection"]["matched"] is True


def test_sigma_engine_marks_curl_outbound_http_connection():
    engine = SigmaEngine(RULES_DIR)
    doc = {
        "event": {
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "action": "network_connection_attempt",
        },
        "network": {
            "direction": "outbound",
            "transport": "tcp",
            "type": "ipv4",
        },
        "process": {
            "pid": 88523,
            "name": "curl",
            "command_line": "curl http://example.com",
            "executable": "/usr/bin/curl",
        },
        "destination": {
            "ip": "104.20.23.154",
            "port": 80,
        },
    }

    result = engine.evaluate(doc)

    assert result["event"]["kind"] == "alert"
    assert result["rule"]["id"] == "lab-network-curl-outbound-http"
    assert result["edr"]["detection"]["matched"] is True
