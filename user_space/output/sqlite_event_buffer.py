import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Iterable, List, Optional


@dataclass(frozen=True)
class EventBufferRecord:
    id: int
    payload: str
    attempts: int
    created_at: float
    next_attempt_at: float
    last_error: Optional[str]


class SQLiteEventBuffer:

    def __init__(
        self,
        db_path: str | Path,
        *,
        max_rows: int = 50_000,
        max_db_size_mb: Optional[int] = 500,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.max_rows = max_rows
        self.max_db_size_bytes = (
            max_db_size_mb * 1024 * 1024 if max_db_size_mb is not None else None
        )

        self._lock = RLock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            timeout=5.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row

        self._configure_connection()
        self._init_schema()

    def _configure_connection(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA busy_timeout=5000")

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS event_buffer (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL,
                    last_error TEXT
                )
                """
            )

            self._conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_event_buffer_ready
                ON event_buffer(next_attempt_at, id)
                """
            )

    def insert(self, payload: str, *, now: Optional[float] = None) -> int:
        now = time.time() if now is None else now

        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO event_buffer(
                    created_at,
                    attempts,
                    next_attempt_at,
                    payload,
                    last_error
                )
                VALUES (?, 0, 0, ?, NULL)
                """,
                (now, payload),
            )

            row_id = int(cursor.lastrowid)
            self.enforce_retention()
            return row_id

    def fetch_ready_batch(
        self,
        *,
        limit: int,
        now: Optional[float] = None,
    ) -> List[EventBufferRecord]:
        now = time.time() if now is None else now

        with self._lock:
            rows = self._conn.execute(
                """
                SELECT id, payload, attempts, created_at, next_attempt_at, last_error
                FROM event_buffer
                WHERE next_attempt_at <= ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()

        return [
            EventBufferRecord(
                id=int(row["id"]),
                payload=str(row["payload"]),
                attempts=int(row["attempts"]),
                created_at=float(row["created_at"]),
                next_attempt_at=float(row["next_attempt_at"]),
                last_error=row["last_error"],
            )
            for row in rows
        ]

    def delete_many(self, ids: Iterable[int]) -> None:
        id_list = list(ids)
        if not id_list:
            return

        placeholders = ",".join("?" for _ in id_list)

        with self._lock:
            self._conn.execute(
                f"DELETE FROM event_buffer WHERE id IN ({placeholders})",
                id_list,
            )

    def mark_failed(
        self,
        ids: Iterable[int],
        *,
        error: str,
        retry_delay_seconds: float,
        now: Optional[float] = None,
    ) -> None:
        id_list = list(ids)
        if not id_list:
            return

        now = time.time() if now is None else now
        next_attempt_at = now + retry_delay_seconds

        placeholders = ",".join("?" for _ in id_list)
        params = [next_attempt_at, error[:1024], *id_list]

        with self._lock:
            self._conn.execute(
                f"""
                UPDATE event_buffer
                SET attempts = attempts + 1,
                    next_attempt_at = ?,
                    last_error = ?
                WHERE id IN ({placeholders})
                """,
                params,
            )

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM event_buffer"
            ).fetchone()
            return int(row["c"])

    def enforce_retention(self) -> None:
        with self._lock:
            if self.max_rows > 0:
                row = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM event_buffer"
                ).fetchone()

                excess = int(row["c"]) - self.max_rows

                if excess > 0:
                    self._delete_oldest_locked(excess)

            if (
                self.max_db_size_bytes is not None
                and self.db_size_bytes() > self.max_db_size_bytes
            ):
                row = self._conn.execute(
                    "SELECT COUNT(*) AS c FROM event_buffer"
                ).fetchone()

                current_count = int(row["c"])

                if current_count > 0:
                    delete_count = max(1, current_count // 10)
                    self._delete_oldest_locked(delete_count)

    def _delete_oldest_locked(self, count: int) -> None:
        self._conn.execute(
            """
            DELETE FROM event_buffer
            WHERE id IN (
                SELECT id
                FROM event_buffer
                ORDER BY id ASC
                LIMIT ?
            )
            """,
            (count,),
        )

    def db_size_bytes(self) -> int:
        total = 0

        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.db_path) + suffix)
            if path.exists():
                total += path.stat().st_size

        return total

    def close(self) -> None:
        with self._lock:
            self._conn.close()