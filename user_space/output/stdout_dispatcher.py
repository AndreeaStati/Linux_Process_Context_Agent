import json
from typing import Any, Dict, TextIO

from output.dispatcher import OutputDispatcher


class StdoutDispatcher(OutputDispatcher):
    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream

    def emit(self, ecs_doc: Dict[str, Any]) -> None:
        print(
            json.dumps(
                ecs_doc,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            file=self.stream,
            flush=True,
        )
