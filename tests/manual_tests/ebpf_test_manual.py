from bcc import BPF
import argparse
import ctypes as ct
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path


TASK_COMM_LEN = 16
FILENAME_LEN = 256
ARG_LEN = 128

EVENT_EXECVE = 1
EVENT_EXECVEAT = 2
EVENT_CONNECT = 3
EVENT_ACCEPT = 4

AF_INET = 2


class Event(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_uint64),

        ("event_type", ct.c_uint32),
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("uid", ct.c_uint32),
        ("auid", ct.c_uint32),

        ("comm", ct.c_char * TASK_COMM_LEN),
        ("filename", ct.c_char * FILENAME_LEN),

        ("argv0", ct.c_char * ARG_LEN),
        ("argv1", ct.c_char * ARG_LEN),
        ("argv2", ct.c_char * ARG_LEN),
        ("argv3", ct.c_char * ARG_LEN),
        ("argv4", ct.c_char * ARG_LEN),
        ("argv5", ct.c_char * ARG_LEN),

        ("saddr", ct.c_uint32),
        ("daddr", ct.c_uint32),

        ("sport", ct.c_uint16),
        ("dport", ct.c_uint16),
        ("family", ct.c_uint16),
    ]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Test funcțional pentru senzorii eBPF/BCC ai agentului."
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Afișează și evenimentele care nu aparțin testului.",
    )

    parser.add_argument(
        "--poll-seconds",
        type=float,
        default=3.0,
        help="Timp suplimentar de polling după generarea evenimentelor.",
    )

    parser.add_argument(
        "--skip-execveat",
        action="store_true",
        help="Nu testează execveat.",
    )

    return parser.parse_args()


ARGS = parse_args()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EBPF_DIR = PROJECT_ROOT / "ebpf"
SENSORS_FILE = EBPF_DIR / "sensors.c"

TEST_PID = os.getpid()

targets = {
    "connect_port": None,
    "accept_sport": None,
    "execveat_helper": None,
    "execveat_pid": None,
}

seen = {
    "execve": [],
    "execveat": [],
    "connect": [],
    "accept": [],
}

stats = {
    "total": 0,
    "noise": 0,
    "unknown_size": 0,
    "unknown_type": 0,
}


def cstr(value):
    raw = bytes(value).split(b"\x00", 1)[0]
    text = raw.decode(errors="replace")

    cleaned = []
    for ch in text:
        if ch.isprintable() or ch in ("\t", " "):
            cleaned.append(ch)
        else:
            cleaned.append("�")

    return "".join(cleaned)


def ip_from_u32(addr):
    if addr == 0:
        return "0.0.0.0"

    return socket.inet_ntoa(struct.pack("<I", addr))


def format_argv(event):
    args = [
        cstr(event.argv0),
        cstr(event.argv1),
        cstr(event.argv2),
        cstr(event.argv3),
        cstr(event.argv4),
        cstr(event.argv5),
    ]

    args = [arg for arg in args if arg]
    return " ".join(args)


def event_label(event_type):
    if event_type == EVENT_EXECVE:
        return "EXECVE"
    if event_type == EVENT_EXECVEAT:
        return "EXECVEAT"
    if event_type == EVENT_CONNECT:
        return "CONNECT"
    if event_type == EVENT_ACCEPT:
        return "ACCEPT"
    return f"UNKNOWN_{event_type}"


def print_event(event, prefix="[EVENT]"):
    comm = cstr(event.comm)
    filename = cstr(event.filename)
    argv = format_argv(event)

    if event.event_type in (EVENT_EXECVE, EVENT_EXECVEAT):
        print(
            f"{prefix} [{event_label(event.event_type)}] "
            f"pid={event.pid} ppid={event.ppid} uid={event.uid} "
            f"auid={event.auid} comm={comm} "
            f"filename={filename} argv=\"{argv}\""
        )

    elif event.event_type == EVENT_CONNECT:
        print(
            f"{prefix} [CONNECT] "
            f"pid={event.pid} ppid={event.ppid} uid={event.uid} "
            f"comm={comm} "
            f"daddr={ip_from_u32(event.daddr)} dport={event.dport} "
            f"family={event.family}"
        )

    elif event.event_type == EVENT_ACCEPT:
        print(
            f"{prefix} [ACCEPT] "
            f"pid={event.pid} ppid={event.ppid} uid={event.uid} "
            f"comm={comm} "
            f"saddr={ip_from_u32(event.saddr)} sport={event.sport} "
            f"family={event.family}"
        )

    else:
        print(
            f"{prefix} [UNKNOWN] "
            f"type={event.event_type} pid={event.pid} ppid={event.ppid} "
            f"uid={event.uid} comm={comm}"
        )


def is_test_execve(event):
    return (
        event.event_type == EVENT_EXECVE
        and event.ppid == TEST_PID
        and cstr(event.filename) == "/bin/true"
    )


def is_test_execveat(event):
    return (
        event.event_type == EVENT_EXECVEAT
        and targets["execveat_pid"] is not None
        and event.pid == targets["execveat_pid"]
    )



def is_test_connect(event):
    return (
        event.event_type == EVENT_CONNECT
        and event.pid == TEST_PID
        and event.family == AF_INET
        and ip_from_u32(event.daddr) == "127.0.0.1"
        and targets["connect_port"] is not None
        and event.dport == targets["connect_port"]
    )


def is_test_accept(event):
    return (
        event.event_type == EVENT_ACCEPT
        and event.pid == TEST_PID
        and event.family == AF_INET
        and ip_from_u32(event.saddr) == "127.0.0.1"
        and targets["accept_sport"] is not None
        and event.sport == targets["accept_sport"]
    )


def handle_event(ctx, data, size):
    stats["total"] += 1

    expected_size = ct.sizeof(Event)

    if size != expected_size:
        stats["unknown_size"] += 1
        print(f"[UNKNOWN_SIZE] size={size}, expected={expected_size}")
        return

    event = Event.from_buffer_copy(ct.string_at(data, size))

    if is_test_execve(event):
        seen["execve"].append(event)
        print_event(event, prefix="[TEST]")

    elif is_test_execveat(event):
        seen["execveat"].append(event)
        print_event(event, prefix="[TEST]")

    elif is_test_connect(event):
        seen["connect"].append(event)
        print_event(event, prefix="[TEST]")

    elif is_test_accept(event):
        seen["accept"].append(event)
        print_event(event, prefix="[TEST]")

    else:
        stats["noise"] += 1

        if ARGS.verbose:
            print_event(event, prefix="[NOISE]")


def poll_for(bpf, seconds):
    deadline = time.time() + seconds

    while time.time() < deadline:
        bpf.ring_buffer_poll(timeout=100)


def build_execveat_helper():
    if ARGS.skip_execveat:
        print("[*] execveat test skipped by --skip-execveat")
        return None

    if shutil.which("gcc") is None:
        print("[!] gcc nu este instalat; execveat test va fi sărit.")
        return None

    helper_src = Path("/tmp/proc_agent_execveat_helper.c")
    helper_bin = Path("/tmp/proc_agent_execveat_helper")

    helper_src.write_text(
        r'''
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

int main(void)
{
    char *argv[] = {"/bin/true", NULL};
    char *envp[] = {NULL};

    syscall(SYS_execveat, AT_FDCWD, "/bin/true", argv, envp, 0);
    return 1;
}
'''.lstrip()
    )

    try:
        subprocess.run(
            [
                "gcc",
                "-O2",
                "-Wall",
                str(helper_src),
                "-o",
                str(helper_bin),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        print("[!] Nu am putut compila helperul execveat.")
        print(exc.stderr)
        return None

    return str(helper_bin)


def trigger_execve():
    subprocess.run(["/bin/true"], check=False)


def trigger_execveat():
    helper = targets["execveat_helper"]

    if not helper:
        return

    proc = subprocess.Popen([helper])
    targets["execveat_pid"] = proc.pid
    proc.wait(timeout=5)



def trigger_connect_and_accept_ipv4():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    host, port = server.getsockname()
    targets["connect_port"] = port

    accepted = {
        "ok": False,
        "peer": None,
    }

    def accept_once():
        try:
            conn, peer = server.accept()
            accepted["ok"] = True
            accepted["peer"] = peer
            conn.close()
        finally:
            server.close()

    t = threading.Thread(target=accept_once)
    t.start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.bind(("127.0.0.1", 0))
    client.connect((host, port))

    client_host, client_port = client.getsockname()
    targets["accept_sport"] = client_port

    client.close()
    t.join(timeout=3)

    if not accepted["ok"]:
        raise RuntimeError("Serverul de test nu a acceptat conexiunea.")


def print_summary():
    print("\n[*] Summary:")
    print(f"    total events received: {stats['total']}")
    print(f"    noise events ignored:  {stats['noise']}")
    print(f"    unknown size events:   {stats['unknown_size']}")
    print(f"    execve:                {len(seen['execve'])}")
    print(f"    execveat:              {len(seen['execveat'])}")
    print(f"    connect:               {len(seen['connect'])}")
    print(f"    accept:                {len(seen['accept'])}")

    print("\n[*] Targets:")
    print(f"    test pid:       {TEST_PID}")
    print(f"    connect dport:  {targets['connect_port']}")
    print(f"    accept sport:   {targets['accept_sport']}")
    print(f"    execveat helper:{targets['execveat_helper']}")
    print(f"    execveat pid:   {targets['execveat_pid']}")


def validate_results():
    missing = []

    if len(seen["execve"]) < 1:
        missing.append("execve")

    if targets["execveat_helper"] is not None and len(seen["execveat"]) < 1:
        missing.append("execveat")

    if len(seen["connect"]) < 1:
        missing.append("connect")

    if len(seen["accept"]) < 1:
        missing.append("accept/accept4")

    if missing:
        print("\n[!] Test FAILED. Lipsesc evenimente:")
        for item in missing:
            print(f"    - {item}")
        return False

    print("\n[+] Test PASSED. Evenimentele principale au fost capturate.")
    return True


def main():
    print("[*] Preparing execveat helper...")
    targets["execveat_helper"] = build_execveat_helper()

    print("[*] Loading BPF program...")
    print(f"    sensors: {SENSORS_FILE}")
    print(f"    include: {EBPF_DIR}")

    bpf = BPF(
        src_file=str(SENSORS_FILE),
        cflags=[f"-I{EBPF_DIR}"],
    )

    bpf["events"].open_ring_buffer(handle_event)

    print(f"[*] Python Event struct size: {ct.sizeof(Event)} bytes")
    print(f"[*] Test PID: {TEST_PID}")
    print("[*] BPF loaded. Generating test events...")

    trigger_execve()
    poll_for(bpf, 0.5)

    trigger_execveat()
    poll_for(bpf, 0.5)

    trigger_connect_and_accept_ipv4()
    poll_for(bpf, ARGS.poll_seconds)

    print_summary()

    print("\n[*] Note:")
    print("    Se afiseaza implicit doar evenimentele generate de test.")
    print("    Foloseste --verbose pentru a vedea si zgomotul de sistem.")
    print("    auid=4294967295 inseamna placeholder (u32)-1.")

    ok = validate_results()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()