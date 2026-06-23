import copy
import json
from types import SimpleNamespace

from pipeline.event_pipeline import EventPipeline


class FakeNormalizer:
    def __init__(self, ecs_doc):
        self.ecs_doc = ecs_doc
        self.called = False
        self.observed_event = None

    def from_kernel_event(self, event):
        self.called = True
        self.observed_event = event
        return copy.deepcopy(self.ecs_doc)


class FakeFilter:
    def __init__(
        self,
        drop=False,
        reason=None,
        call_order=None,
        name="system_noise_filter",
    ):
        self.drop = drop
        self.reason = reason
        self.called = False
        self.observed_value = None
        self.call_order = call_order
        self.name = name

    def evaluate(self, value):
        self.called = True
        self.observed_value = copy.deepcopy(value)

        if self.call_order is not None:
            self.call_order.append(self.name)

        return SimpleNamespace(
            drop=self.drop,
            reason=self.reason,
        )


class FakeProcEnricher:
    def __init__(self, call_order=None):
        self.called = False
        self.call_order = call_order

    def enrich(self, ecs_doc):
        self.called = True

        if self.call_order is not None:
            self.call_order.append("proc_enricher")

        ecs_doc.setdefault("process", {})
        ecs_doc["process"]["command_line"] = "curl http://example.com"
        ecs_doc["process"]["executable"] = "/usr/bin/curl"
        ecs_doc["process"]["name"] = "curl"
        ecs_doc["process"]["hash"] = {
            "sha256": "a" * 64,
        }

        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"].setdefault("enrichment", {})
        ecs_doc["edr"]["enrichment"]["proc"] = {
            "enriched": True,
            "command_line_status": "ok",
            "executable_status": "ok",
            "hash_status": "ok",
        }

        return ecs_doc


class ExplodingProcEnricher:
    def __init__(self):
        self.called = False

    def enrich(self, ecs_doc):
        self.called = True
        raise RuntimeError("proc boom")


class FakeSigmaEngine:
    def __init__(self, call_order=None):
        self.called = False
        self.observed_value = None
        self.call_order = call_order

    def evaluate(self, ecs_doc):
        self.called = True
        self.observed_value = copy.deepcopy(ecs_doc)

        if self.call_order is not None:
            self.call_order.append("sigma_engine")

        ecs_doc.setdefault("event", {})
        ecs_doc["event"]["kind"] = "alert"

        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"]["detection"] = {
            "matched": True,
            "engine": "sigma_edge",
            "ruleset": "local-sigma",
            "rule_id": "lab-process-curl-wget-external-url",
            "rule_title": "Curl Or Wget External URL Execution",
            "severity": "medium",
            "matches": [
                {
                    "rule_id": "lab-process-curl-wget-external-url",
                    "rule_title": "Curl Or Wget External URL Execution",
                    "level": "medium",
                }
            ],
        }

        ecs_doc["rule"] = {
            "id": "lab-process-curl-wget-external-url",
            "name": "Curl Or Wget External URL Execution",
            "level": "medium",
            "ruleset": "local-sigma",
        }

        return ecs_doc


class ExplodingSigmaEngine:
    def __init__(self):
        self.called = False

    def evaluate(self, ecs_doc):
        self.called = True
        raise RuntimeError("sigma boom")


class FakeAlertDeduplicator:
    def __init__(self, call_order=None, drop=False, reason=None):
        self.called = False
        self.observed_value = None
        self.call_order = call_order
        self.drop = drop
        self.reason = reason

    def evaluate(self, ecs_doc):
        self.called = True
        self.observed_value = copy.deepcopy(ecs_doc)

        if self.call_order is not None:
            self.call_order.append("alert_deduplicator")

        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"].setdefault("alert", {})
        ecs_doc["edr"]["alert"]["dedup"] = {
            "enabled": True,
            "mode": "mark",
            "is_duplicate": self.drop,
            "group_id": "abc",
            "window_seconds": 5.0,
            "count": 2 if self.drop else 1,
        }

        return SimpleNamespace(
            ecs_doc=ecs_doc,
            drop=self.drop,
            reason=self.reason,
        )


class ExplodingAlertDeduplicator:
    def __init__(self):
        self.called = False

    def evaluate(self, ecs_doc):
        self.called = True
        raise RuntimeError("dedup boom")


class FakeAlertCorrelator:
    def __init__(self, call_order=None):
        self.called = False
        self.observed_value = None
        self.call_order = call_order

    def process(self, ecs_doc):
        self.called = True
        self.observed_value = copy.deepcopy(ecs_doc)

        if self.call_order is not None:
            self.call_order.append("alert_correlator")

        ecs_doc.setdefault("edr", {})
        ecs_doc["edr"]["correlation"] = {
            "matched": True,
            "engine": "edge_correlator",
            "rule_id": "corr-external-transfer-outbound-http",
            "name": "External Transfer Followed By Outbound HTTP",
            "severity": "high",
            "related_rules": [
                "lab-process-curl-wget-external-url",
                "lab-network-curl-outbound-http",
            ],
        }

        return ecs_doc


class ExplodingAlertCorrelator:
    def __init__(self):
        self.called = False

    def process(self, ecs_doc):
        self.called = True
        raise RuntimeError("correlator boom")


def _base_ecs_doc():
    return {
        "event": {
            "category": ["process"],
            "type": ["start"],
            "action": "process_started",
        },
        "host": {
            "hostname": "ubuntu-1",
        },
        "process": {
            "pid": 123,
            "parent": {
                "pid": 1,
            },
            "name": "bash",
        },
        "user": {
            "id": "1000",
        },
    }


def test_proc_enricher_runs_before_system_noise_filter(capsys):
    call_order = []

    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher(call_order=call_order)
    system_noise_filter = FakeFilter(drop=False, call_order=call_order)

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        debug_drops=False,
    )

    event = object()
    pipeline.process(event)

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert normalizer.called is True
    assert normalizer.observed_event is event
    assert proc_enricher.called is True
    assert system_noise_filter.called is True

    assert call_order == ["proc_enricher", "system_noise_filter"]

    assert system_noise_filter.observed_value["process"]["name"] == "curl"
    assert (
        system_noise_filter.observed_value["process"]["command_line"]
        == "curl http://example.com"
    )
    assert system_noise_filter.observed_value["process"]["executable"] == "/usr/bin/curl"
    assert system_noise_filter.observed_value["process"]["hash"]["sha256"] == "a" * 64

    assert output["process"]["name"] == "curl"
    assert output["process"]["command_line"] == "curl http://example.com"
    assert output["process"]["executable"] == "/usr/bin/curl"
    assert output["process"]["hash"]["sha256"] == "a" * 64
    assert output["edr"]["enrichment"]["proc"]["enriched"] is True


def test_system_noise_filter_can_drop_after_proc_enrichment(capsys):
    call_order = []

    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher(call_order=call_order)
    system_noise_filter = FakeFilter(
        drop=True,
        reason="procfs polling noise",
        call_order=call_order,
    )

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        debug_drops=True,
    )

    pipeline.process(object())

    captured = capsys.readouterr()

    assert normalizer.called is True
    assert proc_enricher.called is True
    assert system_noise_filter.called is True

    assert call_order == ["proc_enricher", "system_noise_filter"]
    assert captured.out == ""
    assert "system_noise_filter" in captured.err
    assert "procfs polling noise" in captured.err


def test_agent_self_filter_stops_pipeline_before_normalizer(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    agent_self_filter = FakeFilter(
        drop=True,
        reason="agent self event",
        name="agent_self_filter",
    )
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=False)

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=agent_self_filter,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        debug_drops=True,
    )

    pipeline.process(object())

    captured = capsys.readouterr()

    assert agent_self_filter.called is True
    assert normalizer.called is False
    assert proc_enricher.called is False
    assert system_noise_filter.called is False

    assert captured.out == ""
    assert "agent_self_filter" in captured.err
    assert "agent self event" in captured.err


def test_pipeline_continues_if_proc_enricher_raises(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = ExplodingProcEnricher()
    system_noise_filter = FakeFilter(drop=False)

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert proc_enricher.called is True
    assert system_noise_filter.called is True
    assert output["process"]["pid"] == 123
    assert output["process"]["name"] == "bash"

    assert "[warn] eroare proc_enricher" in captured.err
    assert "proc boom" in captured.err


def test_sigma_engine_runs_after_system_noise_filter(capsys):
    call_order = []

    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher(call_order=call_order)
    system_noise_filter = FakeFilter(drop=False, call_order=call_order)
    sigma_engine = FakeSigmaEngine(call_order=call_order)

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert call_order == [
        "proc_enricher",
        "system_noise_filter",
        "sigma_engine",
    ]

    assert sigma_engine.called is True
    assert sigma_engine.observed_value["process"]["name"] == "curl"
    assert output["event"]["kind"] == "alert"
    assert output["edr"]["detection"]["matched"] is True


def test_sigma_engine_is_not_called_when_system_noise_filter_drops(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=True, reason="system noise")
    sigma_engine = FakeSigmaEngine()

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        debug_drops=True,
    )

    pipeline.process(object())

    captured = capsys.readouterr()

    assert proc_enricher.called is True
    assert system_noise_filter.called is True
    assert sigma_engine.called is False

    assert captured.out == ""
    assert "system_noise_filter" in captured.err
    assert "system noise" in captured.err


def test_pipeline_continues_if_sigma_engine_raises(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=False)
    sigma_engine = ExplodingSigmaEngine()

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert sigma_engine.called is True
    assert output["process"]["name"] == "curl"

    assert "[warn] eroare sigma_engine" in captured.err
    assert "sigma boom" in captured.err


def test_alert_deduplicator_runs_after_sigma_engine(capsys):
    call_order = []

    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher(call_order=call_order)
    system_noise_filter = FakeFilter(drop=False, call_order=call_order)
    sigma_engine = FakeSigmaEngine(call_order=call_order)
    alert_deduplicator = FakeAlertDeduplicator(call_order=call_order)

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert call_order == [
        "proc_enricher",
        "system_noise_filter",
        "sigma_engine",
        "alert_deduplicator",
    ]

    assert alert_deduplicator.called is True
    assert alert_deduplicator.observed_value["edr"]["detection"]["matched"] is True
    assert output["edr"]["alert"]["dedup"]["is_duplicate"] is False


def test_alert_deduplicator_can_drop_duplicate_alert(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=False)
    sigma_engine = FakeSigmaEngine()
    alert_deduplicator = FakeAlertDeduplicator(
        drop=True,
        reason="same_rule_same_process_within_window",
    )

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        debug_drops=True,
    )

    pipeline.process(object())

    captured = capsys.readouterr()

    assert alert_deduplicator.called is True
    assert captured.out == ""
    assert "alert_deduplicator" in captured.err
    assert "same_rule_same_process_within_window" in captured.err


def test_pipeline_continues_if_alert_deduplicator_raises(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=False)
    sigma_engine = FakeSigmaEngine()
    alert_deduplicator = ExplodingAlertDeduplicator()

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert alert_deduplicator.called is True
    assert output["event"]["kind"] == "alert"
    assert "alert" not in output["edr"]

    assert "[warn] eroare alert_deduplicator" in captured.err
    assert "dedup boom" in captured.err


def test_alert_correlator_runs_after_alert_deduplicator(capsys):
    call_order = []

    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher(call_order=call_order)
    system_noise_filter = FakeFilter(drop=False, call_order=call_order)
    sigma_engine = FakeSigmaEngine(call_order=call_order)
    alert_deduplicator = FakeAlertDeduplicator(call_order=call_order)
    alert_correlator = FakeAlertCorrelator(call_order=call_order)

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        alert_correlator=alert_correlator,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert call_order == [
        "proc_enricher",
        "system_noise_filter",
        "sigma_engine",
        "alert_deduplicator",
        "alert_correlator",
    ]

    assert alert_correlator.called is True
    assert alert_correlator.observed_value["edr"]["detection"]["matched"] is True
    assert (
        alert_correlator.observed_value["edr"]["alert"]["dedup"]["is_duplicate"]
        is False
    )

    assert output["edr"]["correlation"]["matched"] is True
    assert (
        output["edr"]["correlation"]["rule_id"]
        == "corr-external-transfer-outbound-http"
    )


def test_alert_correlator_is_not_called_when_alert_deduplicator_drops(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=False)
    sigma_engine = FakeSigmaEngine()
    alert_deduplicator = FakeAlertDeduplicator(
        drop=True,
        reason="same_rule_same_process_within_window",
    )
    alert_correlator = FakeAlertCorrelator()

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        alert_correlator=alert_correlator,
        debug_drops=True,
    )

    pipeline.process(object())

    captured = capsys.readouterr()

    assert alert_deduplicator.called is True
    assert alert_correlator.called is False

    assert captured.out == ""
    assert "alert_deduplicator" in captured.err
    assert "same_rule_same_process_within_window" in captured.err


def test_pipeline_continues_if_alert_correlator_raises(capsys):
    normalizer = FakeNormalizer(_base_ecs_doc())
    proc_enricher = FakeProcEnricher()
    system_noise_filter = FakeFilter(drop=False)
    sigma_engine = FakeSigmaEngine()
    alert_deduplicator = FakeAlertDeduplicator()
    alert_correlator = ExplodingAlertCorrelator()

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=None,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        alert_correlator=alert_correlator,
        debug_drops=False,
    )

    pipeline.process(object())

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert alert_correlator.called is True

    assert output["event"]["kind"] == "alert"
    assert output["edr"]["detection"]["matched"] is True
    assert output["edr"]["alert"]["dedup"]["is_duplicate"] is False
    assert "correlation" not in output["edr"]

    assert "[warn] eroare alert_correlator" in captured.err
    assert "correlator boom" in captured.err