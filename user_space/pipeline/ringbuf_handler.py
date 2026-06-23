import ctypes
import sys
from typing import Any, Optional

from normalizer.kernel_event import KernelEvent, KERNEL_EVENT_SIZE
from pipeline.event_pipeline import EventPipeline


class RingBufferHandler:

    def __init__(self, pipeline: EventPipeline) -> None:
        self.pipeline = pipeline

    def handle_event(self, ctx: Any, data: Any, size: int) -> None:
        event = self._decode_kernel_event(data, size)

        if event is None:
            return

        self.pipeline.process(event)

    def _decode_kernel_event(self, data: Any, size: int) -> Optional[KernelEvent]:
        if size < KERNEL_EVENT_SIZE:
            print(
                f"[drop] buffer incomplet: {size} < {KERNEL_EVENT_SIZE}",
                file=sys.stderr,
            )
            return None

        try:
            raw = ctypes.string_at(data, KERNEL_EVENT_SIZE)
            return KernelEvent.from_buffer_copy(raw)
        except Exception as exc:
            print(f"[drop] parsare KernelEvent eșuată: {exc}", file=sys.stderr)
            return None