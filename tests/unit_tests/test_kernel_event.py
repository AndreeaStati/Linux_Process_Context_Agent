from normalizer.kernel_event import KERNEL_EVENT_SIZE, KernelEvent


def test_kernel_event_size_matches_c_struct():
    assert KERNEL_EVENT_SIZE == 1088


def test_kernel_event_can_be_instantiated():
    event = KernelEvent()

    assert event.pid == 0
    assert event.ppid == 0
    assert event.uid == 0
    assert event.event_type == 0