import ctypes

from normalizer.kernel_event import KERNEL_EVENT_SIZE
from pipeline.ringbuf_handler import RingBufferHandler


class FakePipeline:
    def __init__(self):
        self.called = False
        self.observed_event = None

    def process(self, event):
        self.called = True
        self.observed_event = event


def test_handle_event_calls_pipeline_when_decode_succeeds(monkeypatch):
    pipeline = FakePipeline()
    handler = RingBufferHandler(pipeline=pipeline)

    fake_event = object()

    monkeypatch.setattr(
        handler,
        "_decode_kernel_event",
        lambda data, size: fake_event,
    )

    handler.handle_event(ctx=None, data=b"x", size=1)

    assert pipeline.called is True
    assert pipeline.observed_event is fake_event


def test_handle_event_does_not_call_pipeline_when_decode_fails(monkeypatch):
    pipeline = FakePipeline()
    handler = RingBufferHandler(pipeline=pipeline)

    monkeypatch.setattr(
        handler,
        "_decode_kernel_event",
        lambda data, size: None,
    )

    handler.handle_event(ctx=None, data=b"x", size=1)

    assert pipeline.called is False
    assert pipeline.observed_event is None


def test_decode_kernel_event_rejects_small_buffer(capsys):
    pipeline = FakePipeline()
    handler = RingBufferHandler(pipeline=pipeline)

    result = handler._decode_kernel_event(
        data=b"x",
        size=KERNEL_EVENT_SIZE - 1,
    )

    captured = capsys.readouterr()

    assert result is None
    assert "buffer incomplet" in captured.err


def test_decode_kernel_event_handles_parse_error(monkeypatch, capsys):
    pipeline = FakePipeline()
    handler = RingBufferHandler(pipeline=pipeline)

    def fake_string_at(data, size):
        raise RuntimeError("ctypes boom")

    monkeypatch.setattr(ctypes, "string_at", fake_string_at)

    result = handler._decode_kernel_event(
        data=b"x" * KERNEL_EVENT_SIZE,
        size=KERNEL_EVENT_SIZE,
    )

    captured = capsys.readouterr()

    assert result is None
    assert "parsare KernelEvent eșuată" in captured.err
    assert "ctypes boom" in captured.err