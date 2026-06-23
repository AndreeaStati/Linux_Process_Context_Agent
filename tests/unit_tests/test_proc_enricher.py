import hashlib
import io
import os

from enricher.proc_enricher import ProcEnricher


FAKE_SHA256 = "a" * 64


def test_read_cmdline_converts_null_separated_arguments(monkeypatch):
    enricher = ProcEnricher()

    def fake_open(path, mode="rb", *args, **kwargs):
        assert path == "/proc/123/cmdline"
        assert "b" in mode
        return io.BytesIO(b"curl\x00http://example.com\x00")

    monkeypatch.setattr("builtins.open", fake_open)

    result = enricher._read_cmdline(123)

    assert result == "curl http://example.com"


def test_read_cmdline_returns_none_for_empty_cmdline(monkeypatch):
    enricher = ProcEnricher()

    def fake_open(path, mode="rb", *args, **kwargs):
        return io.BytesIO(b"")

    monkeypatch.setattr("builtins.open", fake_open)

    result = enricher._read_cmdline(123)

    assert result is None


def test_enrich_adds_command_line_executable_hash_and_corrects_name(monkeypatch):
    enricher = ProcEnricher(enable_hash_cache=False)

    monkeypatch.setattr(
        enricher,
        "_read_cmdline",
        lambda pid: "curl http://example.com",
    )

    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: "/usr/bin/curl",
    )

    monkeypatch.setattr(
        enricher,
        "_sha256_file_with_cache",
        lambda path: FAKE_SHA256,
    )

    ecs_doc = {
        "process": {
            "pid": 123,
            "name": "bash",
        }
    }

    result = enricher.enrich(ecs_doc)

    assert result["process"]["command_line"] == "curl http://example.com"
    assert result["process"]["executable"] == "/usr/bin/curl"
    assert result["process"]["name"] == "curl"
    assert result["process"]["hash"]["sha256"] == FAKE_SHA256

    proc_status = result["edr"]["enrichment"]["proc"]

    assert proc_status["enriched"] is True
    assert proc_status["command_line_status"] == "ok"
    assert proc_status["executable_status"] == "ok"
    assert proc_status["hash_status"] == "ok"


def test_sha256_file_reads_file_incrementally(tmp_path):
    test_file = tmp_path / "fake_binary"
    test_content = b"A" * 5000 + b"B" * 3000

    test_file.write_bytes(test_content)

    expected = hashlib.sha256(test_content).hexdigest()

    enricher = ProcEnricher(chunk_size=4096)

    result = enricher._sha256_file(str(test_file))

    assert result == expected


def test_invalid_pid_is_skipped():
    enricher = ProcEnricher()

    ecs_doc = {
        "process": {
            "name": "curl",
        }
    }

    result = enricher.enrich(ecs_doc)

    proc_status = result["edr"]["enrichment"]["proc"]

    assert proc_status["enriched"] is False
    assert proc_status["command_line_status"] == "skipped"
    assert proc_status["executable_status"] == "skipped"
    assert proc_status["hash_status"] == "skipped"
    assert proc_status["reason"] == "missing or invalid process.pid"


def test_pid_zero_is_skipped():
    enricher = ProcEnricher()

    ecs_doc = {
        "process": {
            "pid": 0,
            "name": "curl",
        }
    }

    result = enricher.enrich(ecs_doc)

    proc_status = result["edr"]["enrichment"]["proc"]

    assert proc_status["enriched"] is False
    assert proc_status["command_line_status"] == "skipped"
    assert proc_status["executable_status"] == "skipped"
    assert proc_status["hash_status"] == "skipped"


def test_short_lived_process_is_handled(monkeypatch):
    enricher = ProcEnricher()

    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(enricher, "_read_cmdline", raise_file_not_found)
    monkeypatch.setattr(os, "readlink", raise_file_not_found)
    monkeypatch.setattr(enricher, "_sha256_file_with_cache", raise_file_not_found)

    ecs_doc = {
        "process": {
            "pid": 123,
            "name": "true",
        }
    }

    result = enricher.enrich(ecs_doc)

    process = result["process"]
    proc_status = result["edr"]["enrichment"]["proc"]

    assert process["command_line"] == "unknown (short-lived process)"
    assert process["executable"] == "unknown (short-lived process)"

    assert proc_status["enriched"] is False
    assert proc_status["command_line_status"] == "short_lived"
    assert proc_status["executable_status"] == "short_lived"
    assert proc_status["hash_status"] == "short_lived"

    assert "hash" not in process or "sha256" not in process["hash"]


def test_permission_denied_is_handled(monkeypatch):
    enricher = ProcEnricher()

    def raise_permission_error(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(enricher, "_read_cmdline", raise_permission_error)
    monkeypatch.setattr(os, "readlink", raise_permission_error)
    monkeypatch.setattr(enricher, "_sha256_file_with_cache", raise_permission_error)

    ecs_doc = {
        "process": {
            "pid": 123,
            "name": "curl",
        }
    }

    result = enricher.enrich(ecs_doc)

    process = result["process"]
    proc_status = result["edr"]["enrichment"]["proc"]

    assert process["command_line"] == "unknown (permission denied)"
    assert process["executable"] == "unknown (permission denied)"

    assert proc_status["enriched"] is False
    assert proc_status["command_line_status"] == "permission_denied"
    assert proc_status["executable_status"] == "permission_denied"
    assert proc_status["hash_status"] == "permission_denied"

    assert "hash" not in process or "sha256" not in process["hash"]


def test_os_error_is_handled(monkeypatch):
    enricher = ProcEnricher()

    def raise_os_error(*args, **kwargs):
        raise OSError("proc read failed")

    monkeypatch.setattr(enricher, "_read_cmdline", raise_os_error)
    monkeypatch.setattr(os, "readlink", raise_os_error)
    monkeypatch.setattr(enricher, "_sha256_file_with_cache", raise_os_error)

    ecs_doc = {
        "process": {
            "pid": 123,
            "name": "curl",
        }
    }

    result = enricher.enrich(ecs_doc)

    proc_status = result["edr"]["enrichment"]["proc"]

    assert proc_status["enriched"] is False
    assert proc_status["command_line_status"] == "os_error"
    assert proc_status["executable_status"] == "os_error"
    assert proc_status["hash_status"] == "os_error"


def test_hash_failure_does_not_create_fake_sha256(monkeypatch):
    enricher = ProcEnricher()

    monkeypatch.setattr(
        enricher,
        "_read_cmdline",
        lambda pid: "curl http://example.com",
    )

    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: "/usr/bin/curl",
    )

    def raise_permission_error(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(
        enricher,
        "_sha256_file_with_cache",
        raise_permission_error,
    )

    ecs_doc = {
        "process": {
            "pid": 123,
            "name": "bash",
        }
    }

    result = enricher.enrich(ecs_doc)

    process = result["process"]
    proc_status = result["edr"]["enrichment"]["proc"]

    assert process["command_line"] == "curl http://example.com"
    assert process["executable"] == "/usr/bin/curl"
    assert process["name"] == "curl"

    assert "hash" not in process or "sha256" not in process["hash"]

    assert proc_status["enriched"] is True
    assert proc_status["command_line_status"] == "ok"
    assert proc_status["executable_status"] == "ok"
    assert proc_status["hash_status"] == "permission_denied"


def test_existing_command_line_is_not_overwritten_when_proc_read_fails(monkeypatch):
    enricher = ProcEnricher()

    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(enricher, "_read_cmdline", raise_file_not_found)

    monkeypatch.setattr(
        os,
        "readlink",
        lambda path: "/usr/bin/true",
    )

    monkeypatch.setattr(
        enricher,
        "_sha256_file_with_cache",
        lambda path: FAKE_SHA256,
    )

    ecs_doc = {
        "process": {
            "pid": 123,
            "name": "bash",
            "command_line": "/bin/true",
        }
    }

    result = enricher.enrich(ecs_doc)

    assert result["process"]["command_line"] == "/bin/true"
    assert result["process"]["executable"] == "/usr/bin/true"
    assert result["process"]["name"] == "true"
    assert result["process"]["hash"]["sha256"] == FAKE_SHA256

    proc_status = result["edr"]["enrichment"]["proc"]

    assert proc_status["command_line_status"] == "short_lived"
    assert proc_status["executable_status"] == "ok"
    assert proc_status["hash_status"] == "ok"


def test_hash_cache_reuses_hash_for_same_file_metadata(monkeypatch, tmp_path):
    test_file = tmp_path / "binary"
    test_file.write_bytes(b"same binary content")

    enricher = ProcEnricher(enable_hash_cache=True)

    calls = {"count": 0}

    def fake_sha256_file(path):
        calls["count"] += 1
        return FAKE_SHA256

    monkeypatch.setattr(enricher, "_sha256_file", fake_sha256_file)

    first = enricher._sha256_file_with_cache(str(test_file))
    second = enricher._sha256_file_with_cache(str(test_file))

    assert first == FAKE_SHA256
    assert second == FAKE_SHA256
    assert calls["count"] == 1