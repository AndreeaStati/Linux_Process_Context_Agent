#!/usr/bin/env python3

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from event_store import append_events, read_last_events
from event_receiver_ui import render_events_page


class IngestHandler(BaseHTTPRequestHandler):
    output_file: Path

    def send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        )

    def send_html(self, status_code, html):
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def get_limit(self, query, default=5, maximum=100):
        try:
            limit = int(query.get("limit", [str(default)])[0])
        except ValueError:
            limit = default

        return max(1, min(limit, maximum))

    def do_GET(self):
        parsed_url = urlparse(self.path)
        query = parse_qs(parsed_url.query)

        if parsed_url.path == "/":
            self.send_json(200, {
                "status": "running",
                "service": "edr-mock-event-receiver",
                "ingest_endpoint": "/api/edr/events",
                "ingest_method": "POST",
                "events_api": "/api/edr/events?limit=5",
                "ui": "/ui?limit=20",
                "output_file": str(self.output_file)
            })
            return

        if parsed_url.path == "/health":
            self.send_json(200, {
                "status": "ok"
            })
            return

        if parsed_url.path == "/api/edr/events":
            limit = self.get_limit(query, default=5, maximum=100)
            events = read_last_events(self.output_file, limit)

            self.send_json(200, {
                "status": "ok",
                "count": len(events),
                "limit": limit,
                "events": events
            })
            return

        if parsed_url.path == "/ui":
            limit = self.get_limit(query, default=20, maximum=100)
            events = read_last_events(self.output_file, limit)
            html = render_events_page(events, limit)

            self.send_html(200, html)
            return

        self.send_json(404, {
            "error": "not found"
        })

    def do_POST(self):
        parsed_url = urlparse(self.path)

        if parsed_url.path != "/api/edr/events":
            self.send_json(404, {
                "error": "not found"
            })
            return

        content_length = int(self.headers.get("Content-Length", "0"))

        if content_length <= 0:
            self.send_json(400, {
                "error": "empty body"
            })
            return

        raw_body = self.rfile.read(content_length)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_json(400, {
                "error": "invalid json"
            })
            return

        if not isinstance(payload, list):
            self.send_json(400, {
                "error": "expected json array"
            })
            return

        received_count = append_events(self.output_file, payload)

        print(f"[+] Received batch: {received_count} events")

        self.send_json(200, {
            "status": "ok",
            "received": received_count
        })

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser(
        description="Mock HTTP ingest server for EDR events"
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)

    parser.add_argument(
        "--output",
        default="data/received_events.jsonl",
        help="File where received events are stored as JSONL",
    )

    args = parser.parse_args()

    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    IngestHandler.output_file = output_file

    server = ThreadingHTTPServer((args.host, args.port), IngestHandler)

    print(
        f"[*] Mock ingest server listening on "
        f"http://{args.host}:{args.port}/api/edr/events"
    )
    print(f"[*] UI available at http://{args.host}:{args.port}/ui?limit=20")
    print(f"[*] Writing received events to {output_file}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    main()