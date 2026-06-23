from dataclasses import dataclass
from typing import Optional, Set, Tuple

from normalizer.constants import EVENT_CONNECT
from normalizer.converters import ipv4_from_kernel_u32
from normalizer.kernel_event import KernelEvent


@dataclass
class FilterDecision:
    drop: bool
    reason: Optional[str] = None


class AgentSelfFilter:

    def __init__(
        self,
        agent_pid: int,
        telemetry_endpoints: Optional[Set[Tuple[str, int]]] = None,
    ) -> None:
        self.agent_pid = int(agent_pid)
        self.agent_related_pids: Set[int] = {self.agent_pid}
        self.telemetry_endpoints = telemetry_endpoints or set()

    def evaluate(self, event: KernelEvent) -> FilterDecision:
        pid = int(event.pid)
        ppid = int(event.ppid)

        if pid in self.agent_related_pids:
            return FilterDecision(
                drop=True,
                reason=f"agent self event pid={pid}",
            )

        if ppid in self.agent_related_pids:
            self.agent_related_pids.add(pid)

            return FilterDecision(
                drop=True,
                reason=f"agent child event pid={pid} ppid={ppid}",
            )

        if int(event.event_type) == EVENT_CONNECT:
            destination_ip = ipv4_from_kernel_u32(event.daddr)
            destination_port = int(event.dport)

            if destination_ip and (
                destination_ip,
                destination_port,
            ) in self.telemetry_endpoints:
                return FilterDecision(
                    drop=True,
                    reason=f"telemetry connection {destination_ip}:{destination_port}",
                )

        return FilterDecision(drop=False)