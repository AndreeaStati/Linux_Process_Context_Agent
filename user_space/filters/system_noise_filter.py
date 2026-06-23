import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class FilterDecision:
    drop: bool
    reason: Optional[str] = None


class SystemNoiseFilter:

    PROC_PID_STAT_RE = re.compile(r"^/proc/\d+/stat$")

    def __init__(
        self,
        drop_vscode_noise: bool = True,
        drop_proc_polling_noise: bool = True,
        drop_process_inventory_noise: bool = True,
        drop_event_receiver_noise: bool = True,
    ) -> None:
        self.drop_vscode_noise = drop_vscode_noise
        self.drop_proc_polling_noise = drop_proc_polling_noise
        self.drop_process_inventory_noise = drop_process_inventory_noise
        self.drop_event_receiver_noise = drop_event_receiver_noise

    def evaluate(self, ecs_doc: Dict[str, Any]) -> FilterDecision:
        process = ecs_doc.get("process", {})

        name = self._as_string(process.get("name"))
        executable = self._as_string(process.get("executable"))
        command_line = self._as_string(process.get("command_line"))
        args = self._as_string_list(process.get("args"))

        if self.drop_event_receiver_noise and self._is_event_receiver_server_noise(
            name=name,
            executable=executable,
            command_line=command_line,
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="event receiver server operational noise",
            )

        if self.drop_vscode_noise and self._is_vscode_server_noise(
            name=name,
            executable=executable,
            command_line=command_line,
        ):
            return FilterDecision(
                drop=True,
                reason="vscode server operational noise",
            )

        if self.drop_proc_polling_noise and self._is_proc_polling_noise(
            name=name,
            executable=executable,
            command_line=command_line,
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="procfs polling noise",
            )

        if self.drop_process_inventory_noise and self._is_process_inventory_noise(
            executable=executable,
            command_line=command_line,
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="process inventory polling noise",
            )

        return FilterDecision(drop=False)

    def _is_event_receiver_server_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        searchable = " ".join(
            [
                name,
                executable,
                command_line,
                " ".join(args),
            ]
        )

        return "event_receiver_server.py" in searchable

    def _is_vscode_server_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
    ) -> bool:
        searchable = " ".join(
            [
                name,
                executable,
                command_line,
            ]
        )

        return ".vscode-server" in searchable

    def _is_proc_polling_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        if name == "cpuUsage.sh":
            return True

        if "cpuUsage.sh" in executable or "cpuUsage.sh" in command_line:
            return True

        if self._is_proc_stat_sed_reader(executable=executable, args=args):
            return True

        if self._is_proc_pid_stat_cat_reader(executable=executable, args=args):
            return True

        return False

    def _is_proc_stat_sed_reader(
        self,
        executable: str,
        args: list[str],
    ) -> bool:
        if self._basename(executable) != "sed":
            return False

        return args == [
            "sed",
            "-n",
            r"s/^cpu\s//p",
            "/proc/stat",
        ]

    def _is_proc_pid_stat_cat_reader(
        self,
        executable: str,
        args: list[str],
    ) -> bool:
        if self._basename(executable) != "cat":
            return False

        if len(args) != 2:
            return False

        return bool(self.PROC_PID_STAT_RE.match(args[1]))

    def _is_process_inventory_noise(
        self,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        if args == ["which", "ps"]:
            return True

        if args == ["/bin/sh", "-c", "which ps"]:
            return True

        if args == [
            "/usr/bin/ps",
            "-ax",
            "-o",
            "pid=,ppid=,pcpu=,pmem=,command=",
        ]:
            return True

        if args == [
            "/bin/sh",
            "-c",
            "/usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,command=",
        ]:
            return True

        if command_line in {
            "which ps",
            "/bin/sh -c 'which ps'",
            "/usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,command=",
            "/bin/sh -c '/usr/bin/ps -ax -o pid=,ppid=,pcpu=,pmem=,command='",
        }:
            return True

        if args == [
            "git",
            "worktree",
            "list",
            "--porcelain",
        ]:
            return True

        if command_line == "git worktree list --porcelain":
            return True

        return False

    def _basename(self, path: str) -> str:
        if not path:
            return ""

        return Path(path).name

    def _as_string(self, value: Any) -> str:
        if value is None:
            return ""

        return str(value)

    def _as_string_list(self, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []

        return [
            str(item)
            for item in value
            if item is not None
        ]