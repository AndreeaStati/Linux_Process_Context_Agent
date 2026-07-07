import json
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


def append_events(output_file: Path, events: list) -> int:
    received_at = datetime.now(timezone.utc).isoformat()

    with output_file.open("a", encoding="utf-8") as f:
        for event in events:
            record = {
                "received_at": received_at,
                "event": event,
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return len(events)


def read_last_events(output_file: Path, limit: int) -> list:
    if not output_file.exists():
        return []

    last_lines = deque(maxlen=limit)

    with output_file.open("r", encoding="utf-8") as f:
        for line in f:
            last_lines.append(line)

    records = []

    for line in last_lines:
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records