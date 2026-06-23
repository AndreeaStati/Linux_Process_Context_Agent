import ctypes

from .constants import TASK_COMM_LEN, FILENAME_LEN, ARG_LEN


class KernelEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),

        ("event_type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("auid", ctypes.c_uint32),

        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * FILENAME_LEN),

        ("argv0", ctypes.c_char * ARG_LEN),
        ("argv1", ctypes.c_char * ARG_LEN),
        ("argv2", ctypes.c_char * ARG_LEN),
        ("argv3", ctypes.c_char * ARG_LEN),
        ("argv4", ctypes.c_char * ARG_LEN),
        ("argv5", ctypes.c_char * ARG_LEN),

        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),

        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("family", ctypes.c_uint16),
    ]


KERNEL_EVENT_SIZE = ctypes.sizeof(KernelEvent)