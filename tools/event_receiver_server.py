#!/usr/bin/env python3

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class IngestHandler(BaseHTTPRequestHandler):
    output_file: Path

    def do_POST(self):
        if self.path != "/api/edr/events":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")
            return

        content_length = int(self.headers.get("Content-Length", "0"))

        if content_length <= 0:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"empty body\n")
            return

        raw_body = self.rfile.read(content_length)

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid json\n")
            return

        if not isinstance(payload, list):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"expected json array\n")
            return

        received_at = datetime.now(timezone.utc).isoformat()

        with self.output_file.open("a", encoding="utf-8") as f:
            for event in payload:
                record = {
                    "received_at": received_at,
                    "event": event,
                }
                f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(f"[+] Received batch: {len(payload)} events")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        response = {
            "status": "ok",
            "received": len(payload),
        }
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        return


def main():
    parser = argparse.ArgumentParser(description="Mock HTTP ingest server for EDR events")
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

    print(f"[*] Mock ingest server listening on http://{args.host}:{args.port}/api/edr/events")
    print(f"[*] Writing received events to {output_file}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    main()