import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_CONFIG: Dict[str, Any] = {
    "agent": {
        "debug_drops": False,
        "self_filter": {
            "enabled": True,
        },
    },
    "ebpf": {
        "sensors_path": "ebpf/sensors.c",
        "structures_path": "ebpf/structures.h",
    },
    "output": {
        "mode": "stdout",
        "debug": False,
    },
    "enrichment": {
        "proc_enricher": {
            "enabled": True,
            "chunk_size": 4096,
            "enable_hash_cache": True,
        },
    },
    "filters": {
        "system_noise": {
            "enabled": True,
            "drop_vscode_noise": True,
            "drop_proc_polling_noise": True,
            "drop_process_inventory_noise": True,
            "drop_event_receiver_noise": True,
        },
    },
    "rules": {
        "sigma": {
            "enabled": True,
            "rules_dir": "rules",
        },
    },
    "deduplication": {
        "enabled": True,
        "mode": "mark",
        "window_seconds": 5.0,
    },
    "correlation": {
        "enabled": True,
        "window_seconds": 60.0,
        "ignore_duplicates": True,
    },
    "http": {
        "endpoint": "http://127.0.0.1:8080/api/edr/events",
        "batch_size": 50,
        "flush_interval_seconds": 1.0,
        "timeout_seconds": 5.0,
        "auth_token_env": "EDR_HTTP_AUTH_TOKEN",
    },
    "sqlite": {
        "db_path": "data/agent_events.db",
        "max_rows": 50000,
        "max_db_size_mb": 500,
    },
}


def load_config(config_path: Optional[str | Path]) -> Dict[str, Any]:
    """
    Încarcă configurația agentului.

    Ordinea priorității:
      1. valori implicite din DEFAULT_CONFIG
      2. valori din fișierul YAML
      3. variabile de mediu, pentru compatibilitate cu rulările existente
    """
    config = deepcopy(DEFAULT_CONFIG)

    if config_path is not None:
        path = Path(config_path)

        if not path.exists():
            raise FileNotFoundError(f"Fișierul de configurare nu există: {path}")

        with path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}

        if not isinstance(loaded, dict):
            raise ValueError(f"Config invalid în {path}: rădăcina trebuie să fie un obiect YAML")

        _deep_merge(config, loaded)

    _apply_env_overrides(config)

    return config


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> None:
    for key, value in override.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _apply_env_overrides(config: Dict[str, Any]) -> None:
    """
    Păstrează compatibilitatea cu comenzile existente de forma:

      EDR_OUTPUT_MODE=http
      EDR_HTTP_ENDPOINT=...
      AGENT_EVENTS_DB=...
    """
    if "EDR_OUTPUT_MODE" in os.environ:
        config["output"]["mode"] = os.environ["EDR_OUTPUT_MODE"].lower()

    if "EDR_OUTPUT_DEBUG" in os.environ:
        config["output"]["debug"] = _env_bool("EDR_OUTPUT_DEBUG")

    if "EDR_HTTP_ENDPOINT" in os.environ:
        config["http"]["endpoint"] = os.environ["EDR_HTTP_ENDPOINT"]

    if "AGENT_EVENTS_DB" in os.environ:
        config["sqlite"]["db_path"] = os.environ["AGENT_EVENTS_DB"]

    if "EDR_HTTP_BATCH_SIZE" in os.environ:
        config["http"]["batch_size"] = int(os.environ["EDR_HTTP_BATCH_SIZE"])

    if "EDR_HTTP_FLUSH_INTERVAL" in os.environ:
        config["http"]["flush_interval_seconds"] = float(os.environ["EDR_HTTP_FLUSH_INTERVAL"])

    if "EDR_HTTP_TIMEOUT" in os.environ:
        config["http"]["timeout_seconds"] = float(os.environ["EDR_HTTP_TIMEOUT"])

    if "AGENT_EVENT_DB_MAX_ROWS" in os.environ:
        config["sqlite"]["max_rows"] = int(os.environ["AGENT_EVENT_DB_MAX_ROWS"])

    if "AGENT_EVENT_DB_MAX_SIZE_MB" in os.environ:
        config["sqlite"]["max_db_size_mb"] = int(os.environ["AGENT_EVENT_DB_MAX_SIZE_MB"])


def _env_bool(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "true", "yes", "on")