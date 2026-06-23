import socket
import struct

from filters.agent_self_filter import AgentSelfFilter
from normalizer.constants import EVENT_CONNECT, EVENT_EXECVE
from normalizer.kernel_event import KernelEvent


def kernel_u32_from_ipv4(ip: str) -> int:
    return struct.unpack("=I", socket.inet_aton(ip))[0]


def make_event(
    pid: int = 1234,
    ppid: int = 1000,
    event_type: int = EVENT_EXECVE,
) -> KernelEvent:
    event = KernelEvent()
    event.pid = pid
    event.ppid = ppid
    event.event_type = event_type
    return event


def test_drops_agent_own_pid():
    agent_filter = AgentSelfFilter(agent_pid=5000)

    event = make_event(pid=5000, ppid=1000)

    decision = agent_filter.evaluate(event)

    assert decision.drop is True
    assert "agent self event" in decision.reason


def test_drops_agent_child_process():
    agent_filter = AgentSelfFilter(agent_pid=5000)

    event = make_event(pid=5001, ppid=5000)

    decision = agent_filter.evaluate(event)

    assert decision.drop is True
    assert "agent child event" in decision.reason
    assert 5001 in agent_filter.agent_related_pids


def test_drops_agent_grandchild_process_after_child_is_tracked():
    agent_filter = AgentSelfFilter(agent_pid=5000)

    child_event = make_event(pid=5001, ppid=5000)
    agent_filter.evaluate(child_event)

    grandchild_event = make_event(pid=5002, ppid=5001)

    decision = agent_filter.evaluate(grandchild_event)

    assert decision.drop is True
    assert "agent child event" in decision.reason
    assert 5002 in agent_filter.agent_related_pids


def test_allows_unrelated_process():
    agent_filter = AgentSelfFilter(agent_pid=5000)

    event = make_event(pid=6000, ppid=1000)

    decision = agent_filter.evaluate(event)

    assert decision.drop is False
    assert decision.reason is None


def test_drops_configured_telemetry_connection():
    agent_filter = AgentSelfFilter(
        agent_pid=5000,
        telemetry_endpoints={
            ("192.168.1.100", 5044),
        },
    )

    event = make_event(
        pid=6000,
        ppid=1000,
        event_type=EVENT_CONNECT,
    )
    event.daddr = kernel_u32_from_ipv4("192.168.1.100")
    event.dport = 5044

    decision = agent_filter.evaluate(event)

    assert decision.drop is True
    assert "telemetry connection" in decision.reason


def test_allows_non_telemetry_connection():
    agent_filter = AgentSelfFilter(
        agent_pid=5000,
        telemetry_endpoints={
            ("192.168.1.100", 5044),
        },
    )

    event = make_event(
        pid=6000,
        ppid=1000,
        event_type=EVENT_CONNECT,
    )
    event.daddr = kernel_u32_from_ipv4("8.8.8.8")
    event.dport = 53

    decision = agent_filter.evaluate(event)

    assert decision.drop is False
    assert decision.reason is None