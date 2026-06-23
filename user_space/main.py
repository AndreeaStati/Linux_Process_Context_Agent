import os
import sys
import argparse
from pathlib import Path

from bcc import BPF

from normalizer.ecs_normalizer import EcsNormalizer
from normalizer.kernel_event import KERNEL_EVENT_SIZE

from pipeline.event_pipeline import EventPipeline
from pipeline.ringbuf_handler import RingBufferHandler

from filters.agent_self_filter import AgentSelfFilter
from filters.system_noise_filter import SystemNoiseFilter

from enricher.proc_enricher import ProcEnricher

from detection.sigma_engine import SigmaEngine

from alerting.deduplicator import AlertDeduplicator
from alerting.correlator import AlertCorrelator

from output.http_shipper import HttpSQLiteDispatcher
from output.stdout_dispatcher import StdoutDispatcher

from config_loader import load_config


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent


def parse_args():
    parser = argparse.ArgumentParser(
        description="Agent EDR Linux bazat pe eBPF"
    )

    parser.add_argument(
        "--config",
        default=str(PROJECT_DIR / "config" / "dev.yaml"),
        help="Calea către fișierul YAML de configurare",
    )

    return parser.parse_args()


def resolve_project_path(path_value: str | Path) -> Path:
    path = Path(path_value)

    if path.is_absolute():
        return path

    return PROJECT_DIR / path


def build_output_dispatcher(config):
    output_mode = config["output"]["mode"].lower()
    output_debug = bool(config["output"].get("debug", False))

    if output_mode == "stdout":
        print("[*] OutputDispatcher: stdout", file=sys.stderr)
        return StdoutDispatcher()

    if output_mode == "http":
        http_config = config["http"]
        sqlite_config = config["sqlite"]

        endpoint = http_config["endpoint"]
        db_path = resolve_project_path(sqlite_config["db_path"])
        db_path.parent.mkdir(parents=True, exist_ok=True)

        auth_token = None
        auth_token_env = http_config.get("auth_token_env")

        if auth_token_env:
            auth_token = os.environ.get(auth_token_env)

        print(
            f"[*] OutputDispatcher: HTTP REST endpoint={endpoint}, "
            f"local_db={db_path}",
            file=sys.stderr,
        )

        return HttpSQLiteDispatcher(
            endpoint_url=endpoint,
            db_path=db_path,
            batch_size=int(http_config["batch_size"]),
            flush_interval_seconds=float(http_config["flush_interval_seconds"]),
            request_timeout_seconds=float(http_config["timeout_seconds"]),
            max_rows=int(sqlite_config["max_rows"]),
            max_db_size_mb=int(sqlite_config["max_db_size_mb"]),
            auth_token=auth_token,
            debug=output_debug,
        )

    raise RuntimeError(
        f"Mod output necunoscut: {output_mode}. "
        "Valori acceptate: stdout, http"
    )


def main() -> None:
    args = parse_args()
    config = load_config(args.config)

    ebpf_config = config["ebpf"]
    sensors_path = resolve_project_path(ebpf_config["sensors_path"])
    structures_path = resolve_project_path(ebpf_config["structures_path"])
    ebpf_dir = sensors_path.parent

    sigma_config = config["rules"]["sigma"]
    rules_dir = resolve_project_path(sigma_config["rules_dir"])

    print(f"[*] Config loaded: {args.config}", file=sys.stderr)
    print(f"[*] KernelEvent size: {KERNEL_EVENT_SIZE} bytes", file=sys.stderr)
    print(f"[*] Agent self-filter PID: {os.getpid()}", file=sys.stderr)
    print(f"[*] sensors.c: {sensors_path}", file=sys.stderr)
    print(f"[*] structures.h: {structures_path}", file=sys.stderr)
    print(f"[*] rules/: {rules_dir}", file=sys.stderr)

    if not sensors_path.exists():
        print(f"[!] Nu găsesc sensors.c la: {sensors_path}", file=sys.stderr)
        sys.exit(1)

    if not structures_path.exists():
        print(f"[!] Nu găsesc structures.h la: {structures_path}", file=sys.stderr)
        sys.exit(1)

    if not rules_dir.exists():
        print(f"[!] Nu găsesc rules/ la: {rules_dir}", file=sys.stderr)
        sys.exit(1)

    proc_enricher = None
    proc_enricher_config = config["enrichment"]["proc_enricher"]

    if proc_enricher_config.get("enabled", True):
        proc_enricher = ProcEnricher(
            chunk_size=int(proc_enricher_config["chunk_size"]),
            enable_hash_cache=bool(proc_enricher_config["enable_hash_cache"]),
        )

    normalizer = EcsNormalizer()

    agent_self_filter = None

    if config["agent"]["self_filter"].get("enabled", True):
        agent_self_filter = AgentSelfFilter(
            agent_pid=os.getpid(),
            telemetry_endpoints=set(),
        )

    system_noise_filter = None
    system_noise_config = config["filters"]["system_noise"]

    if system_noise_config.get("enabled", True):
        system_noise_filter = SystemNoiseFilter(
            drop_vscode_noise=bool(system_noise_config["drop_vscode_noise"]),
            drop_proc_polling_noise=bool(system_noise_config["drop_proc_polling_noise"]),
            drop_process_inventory_noise=bool(system_noise_config["drop_process_inventory_noise"]),
            drop_event_receiver_noise=bool(system_noise_config["drop_event_receiver_noise"]),
        )

    sigma_engine = SigmaEngine(
        rules_dir=rules_dir,
        enabled=bool(sigma_config.get("enabled", True)),
    )

    print(f"[*] Sigma rules loaded: {len(sigma_engine.rules)}", file=sys.stderr)

    dedup_config = config["deduplication"]

    alert_deduplicator = AlertDeduplicator(
        window_seconds=float(dedup_config["window_seconds"]),
        mode=dedup_config["mode"],
        enabled=bool(dedup_config.get("enabled", True)),
    )

    print(
        f"[*] AlertDeduplicator enabled: "
        f"mode={dedup_config['mode']}, "
        f"window={float(dedup_config['window_seconds'])}s",
        file=sys.stderr,
    )

    alert_correlator = None
    correlation_config = config["correlation"]

    if correlation_config.get("enabled", True):
        alert_correlator = AlertCorrelator(
            window_seconds=float(correlation_config["window_seconds"]),
            ignore_duplicates=bool(correlation_config["ignore_duplicates"]),
        )

        print(
            f"[*] AlertCorrelator enabled: "
            f"window={alert_correlator.window_seconds}s",
            file=sys.stderr,
        )
    else:
        print("[*] AlertCorrelator disabled", file=sys.stderr)

    output_dispatcher = build_output_dispatcher(config)
    output_dispatcher.start()

    pipeline = EventPipeline(
        normalizer=normalizer,
        agent_self_filter=agent_self_filter,
        system_noise_filter=system_noise_filter,
        proc_enricher=proc_enricher,
        sigma_engine=sigma_engine,
        alert_deduplicator=alert_deduplicator,
        alert_correlator=alert_correlator,
        debug_drops=bool(config["agent"].get("debug_drops", False)),
        output_dispatcher=output_dispatcher,
    )

    handler = RingBufferHandler(
        pipeline=pipeline,
    )

    try:
        bpf = BPF(
            src_file=str(sensors_path),
            cflags=[f"-I{ebpf_dir}"],
        )

        bpf["events"].open_ring_buffer(handler.handle_event)

        print("[*] BPF loaded. Polling ring buffer...", file=sys.stderr)

        while True:
            try:
                bpf.ring_buffer_poll()
            except KeyboardInterrupt:
                print("\n[*] Stopped.", file=sys.stderr)
                break
    finally:
        output_dispatcher.stop()


if __name__ == "__main__":
    main()