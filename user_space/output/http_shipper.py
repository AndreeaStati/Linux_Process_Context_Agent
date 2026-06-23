import json
import random
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from output.dispatcher import OutputDispatcher
from output.sqlite_event_buffer import SQLiteEventBuffer, EventBufferRecord


@dataclass(frozen=True)
class DeliveryResult:
    success: bool
    retryable: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


class HttpSQLiteDispatcher(OutputDispatcher):

    def __init__(
        self,
        *,
        endpoint_url: str,
        db_path: str | Path,
        batch_size: int = 50,
        flush_interval_seconds: float = 1.0,
        request_timeout_seconds: float = 5.0,
        base_backoff_seconds: float = 2.0,
        max_backoff_seconds: float = 60.0,
        max_rows: int = 50_000,
        max_db_size_mb: int = 500,
        auth_token: Optional[str] = None,
        user_agent: str = "licenta-ebpf-edr/1.0",
        debug: bool = False,
    ) -> None:
        if batch_size <= 0:
            raise ValueError("batch_size trebuie să fie pozitiv")

        self.endpoint_url = endpoint_url
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.base_backoff_seconds = base_backoff_seconds
        self.max_backoff_seconds = max_backoff_seconds
        self.auth_token = auth_token
        self.user_agent = user_agent
        self.debug = debug

        self.event_buffer = SQLiteEventBuffer(
            db_path=db_path,
            max_rows=max_rows,
            max_db_size_mb=max_db_size_mb,
        )

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return

        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._worker_loop,
            name="edr-http-dispatcher",
            daemon=True,
        )

        self._thread.start()

    def emit(self, ecs_doc: Dict[str, Any]) -> None:
        self._ensure_event_id(ecs_doc)

        payload = json.dumps(
            ecs_doc,
            ensure_ascii=False,
            separators=(",", ":"),
        )

        # self.event_buffer.insert(payload)
        row_id = self.event_buffer.insert(payload)

        self._debug(
            f"saved event row_id={row_id} "
            f"event_id={ecs_doc.get('event', {}).get('id')} "
            f"action={ecs_doc.get('event', {}).get('action')}"
        )

    def stop(self) -> None:
        self._stop_event.set()

        if self._thread is not None:
            self._thread.join(
                timeout=self.request_timeout_seconds + self.flush_interval_seconds + 1.0
            )

            if self._thread.is_alive():
                print(
                    "[warn] http_dispatcher thread did not stop cleanly; "
                    "leaving SQLite connection open until process exit",
                    file=sys.stderr,
                )
                return

        self.event_buffer.close()

    def _ensure_event_id(self, ecs_doc: Dict[str, Any]) -> None:
        event = ecs_doc.setdefault("event", {})

        if not event.get("id"):
            event["id"] = str(uuid.uuid4())

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                batch = self.event_buffer.fetch_ready_batch(
                    limit=self.batch_size
                )

                if not batch:
                    self._stop_event.wait(self.flush_interval_seconds)
                    continue

                self._debug(
                    f"sending batch size={len(batch)} endpoint={self.endpoint_url}"
                )

                result = self._deliver_batch(batch)
                ids = [record.id for record in batch]

                if result.success:
                    self.event_buffer.delete_many(ids)

                    self._debug(
                        f"delivered batch size={len(ids)} "
                        f"status={result.status_code} deleted_from_db=true"
                    )

                    continue

                max_attempts = max(record.attempts for record in batch)
                retry_delay = self._compute_backoff(max_attempts)

                if not result.retryable:
                    retry_delay = max(retry_delay, 3600.0)

                self.event_buffer.mark_failed(
                    ids,
                    error=result.error or "unknown delivery error",
                    retry_delay_seconds=retry_delay,
                )

                self._debug(
                    f"delivery failed batch_size={len(ids)} "
                    f"status={result.status_code} "
                    f"retryable={result.retryable} "
                    f"saved_in_db=true "
                    f"next_retry_in={retry_delay:.1f}s "
                    f"error={result.error}"
                )

                self._stop_event.wait(
                    min(self.flush_interval_seconds, retry_delay)
                )

            except Exception as exc:
                print(
                    f"[warn] http_dispatcher worker error: {exc}",
                    file=sys.stderr,
                )
                self._stop_event.wait(self.flush_interval_seconds)

    def _deliver_batch(
        self,
        batch: List[EventBufferRecord],
    ) -> DeliveryResult:
        try:
            events = [json.loads(record.payload) for record in batch]
        except json.JSONDecodeError as exc:
            return DeliveryResult(
                success=False,
                retryable=False,
                error=f"invalid local JSON payload: {exc}",
            )

        body = json.dumps(
            events,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }

        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        request = urllib.request.Request(
            self.endpoint_url,
            data=body,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.request_timeout_seconds,
            ) as response:
                status = response.getcode()

            self._debug(
                f"HTTP response status={status} batch_size={len(batch)}"
            )

            if 200 <= status < 300:
                return DeliveryResult(
                    success=True,
                    retryable=False,
                    status_code=status,
                )

            return DeliveryResult(
                success=False,
                retryable=self._is_retryable_status(status),
                error=f"HTTP {status}",
            )

        except urllib.error.HTTPError as exc:
            self._debug(
                f"HTTP error status={exc.code} reason={exc.reason}"
            )

            return DeliveryResult(
                success=False,
                retryable=self._is_retryable_status(exc.code),
                status_code=exc.code,
                error=f"HTTP {exc.code}: {exc.reason}",
            )

        except (urllib.error.URLError, TimeoutError) as exc:
            self._debug(f"network error: {exc}")

            return DeliveryResult(
                success=False,
                retryable=True,
                error=str(exc),
            )

    def _is_retryable_status(self, status: int) -> bool:
        return status in (408, 429) or 500 <= status <= 599

    def _compute_backoff(self, attempts: int) -> float:
        delay = min(
            self.max_backoff_seconds,
            self.base_backoff_seconds * (2 ** max(0, attempts)),
        )

        jitter = random.uniform(0, delay * 0.1)

        return min(self.max_backoff_seconds, delay + jitter)

    def _debug(self, message: str) -> None:
        if self.debug:
            print(f"[http_dispatcher] {message}", file=sys.stderr)