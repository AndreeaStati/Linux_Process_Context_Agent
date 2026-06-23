import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from output.http_shipper import HttpSQLiteDispatcher
from output.sqlite_spool import SQLiteSpool


def test_sqlite_spool_insert_fetch_and_delete(tmp_path):
    spool = SQLiteSpool(tmp_path / "spool.db", max_rows=100, max_db_size_mb=None)

    row_id = spool.insert('{"event":{"action":"process_started"}}', now=10.0)
    batch = spool.fetch_ready_batch(limit=10, now=11.0)

    assert len(batch) == 1
    assert batch[0].id == row_id
    assert batch[0].attempts == 0
    assert json.loads(batch[0].payload)["event"]["action"] == "process_started"

    spool.delete_many([row_id])
    assert spool.count() == 0

    spool.close()


def test_sqlite_spool_retention_deletes_oldest_rows(tmp_path):
    spool = SQLiteSpool(tmp_path / "spool.db", max_rows=2, max_db_size_mb=None)

    first = spool.insert('{"n":1}', now=1.0)
    second = spool.insert('{"n":2}', now=2.0)
    third = spool.insert('{"n":3}', now=3.0)

    batch = spool.fetch_ready_batch(limit=10, now=4.0)
    ids = [record.id for record in batch]

    assert first not in ids
    assert ids == [second, third]
    assert spool.count() == 2

    spool.close()


class _CaptureHandler(BaseHTTPRequestHandler):
    received_bodies = []
    status_code = 200

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        type(self).received_bodies.append(body)
        self.send_response(type(self).status_code)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        return


def _start_server(status_code=200):
    class Handler(_CaptureHandler):
        received_bodies = []

    Handler.status_code = status_code
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, Handler


def _wait_until(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_http_sqlite_dispatcher_delivers_batch_and_deletes_rows(tmp_path):
    server, handler = _start_server(status_code=200)
    endpoint = f"http://127.0.0.1:{server.server_port}/events"

    dispatcher = HttpSQLiteDispatcher(
        endpoint_url=endpoint,
        db_path=tmp_path / "spool.db",
        batch_size=10,
        flush_interval_seconds=0.05,
        request_timeout_seconds=1.0,
        max_rows=100,
        max_db_size_mb=10,
    )

    try:
        dispatcher.start()
        dispatcher.emit({"event": {"action": "process_started"}, "process": {"pid": 123}})
        dispatcher.emit({"event": {"action": "network_connection_attempt"}})

        assert _wait_until(lambda: dispatcher.spool.count() == 0)
        assert len(handler.received_bodies) >= 1

        received_events = []
        for body in handler.received_bodies:
            received_events.extend(json.loads(body))

        assert len(received_events) == 2
        assert all(event["event"].get("id") for event in received_events)
    finally:
        dispatcher.stop()
        server.shutdown()


def test_http_sqlite_dispatcher_keeps_rows_on_retryable_failure(tmp_path):
    server, handler = _start_server(status_code=500)
    endpoint = f"http://127.0.0.1:{server.server_port}/events"

    dispatcher = HttpSQLiteDispatcher(
        endpoint_url=endpoint,
        db_path=tmp_path / "spool.db",
        batch_size=10,
        flush_interval_seconds=0.05,
        request_timeout_seconds=1.0,
        base_backoff_seconds=0.1,
        max_backoff_seconds=0.2,
        max_rows=100,
        max_db_size_mb=10,
    )

    try:
        dispatcher.start()
        dispatcher.emit({"event": {"action": "process_started"}})

        assert _wait_until(lambda: len(handler.received_bodies) >= 1)
        assert dispatcher.spool.count() == 1
    finally:
        dispatcher.stop()
        server.shutdown()
