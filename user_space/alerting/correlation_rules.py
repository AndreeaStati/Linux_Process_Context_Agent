from __future__ import annotations

from .correlation_models import CorrelationRule


DEFAULT_CORRELATION_RULES = [
    CorrelationRule(
        rule_id="corr-external-transfer-outbound-http",
        name="External Transfer Followed By Outbound HTTP",
        severity="high",
        required_rule_ids={
            "lab-process-curl-wget-external-url",
            "lab-network-curl-outbound-http",
        },
        summary=(
            "Procesul a fost executat cu URL extern și a inițiat "
            "conexiuni outbound HTTP/HTTPS."
        ),
    ),
    CorrelationRule(
        rule_id="corr-shell-inline-network-activity",
        name="Shell Inline Command With Network Activity",
        severity="high",
        required_rule_ids={
            "lab-process-shell-inline-command",
            "lab-network-curl-outbound-http",
        },
        summary=(
            "O comandă inline prin shell a fost urmată de activitate "
            "de rețea outbound HTTP/HTTPS."
        ),
    ),
    CorrelationRule(
        rule_id="corr-shell-inline-external-transfer",
        name="Shell Inline Command With External Transfer Tool",
        severity="high",
        required_rule_ids={
            "lab-process-shell-inline-command",
            "lab-process-curl-wget-external-url",
        },
        summary=(
            "O comandă inline prin shell a lansat sau a fost asociată "
            "cu un utilitar de transfer extern."
        ),
    ),
    CorrelationRule(
        rule_id="corr-temp-exec-reverse-shell-port",
        name="Temporary Directory Execution With Reverse Shell Port",
        severity="critical",
        required_rule_ids={
            "lab-process-execution-from-writable-tmp",
            "lab-network-outbound-reverse-shell-port",
        },
        summary=(
            "Un proces lansat dintr-un director temporar a inițiat "
            "o conexiune către un port asociat frecvent cu reverse shell."
        ),
    ),
]