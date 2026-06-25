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
        drop_shell_startup_noise: bool = True,
        drop_development_git_noise: bool = True,
        drop_known_sleep_polling_noise: bool = False,
    ) -> None:
        self.drop_vscode_noise = drop_vscode_noise
        self.drop_proc_polling_noise = drop_proc_polling_noise
        self.drop_process_inventory_noise = drop_process_inventory_noise
        self.drop_event_receiver_noise = drop_event_receiver_noise
        self.drop_shell_startup_noise = drop_shell_startup_noise
        self.drop_development_git_noise = drop_development_git_noise
        self.drop_known_sleep_polling_noise = drop_known_sleep_polling_noise

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
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="vscode server operational noise",
            )

        if self.drop_shell_startup_noise and self._is_shell_startup_noise(
            name=name,
            executable=executable,
            command_line=command_line,
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="shell startup helper noise",
            )

        if self.drop_development_git_noise and self._is_development_git_noise(
            name=name,
            executable=executable,
            command_line=command_line,
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="development git background query noise",
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

        if self.drop_known_sleep_polling_noise and self._is_known_sleep_polling_noise(
            name=name,
            executable=executable,
            command_line=command_line,
            args=args,
        ):
            return FilterDecision(
                drop=True,
                reason="known sleep polling noise",
            )

        return FilterDecision(drop=False)

    def _is_event_receiver_server_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        searchable = self._join_searchable(
            name,
            executable,
            command_line,
            " ".join(args),
        )

        return "event_receiver_server.py" in searchable

    def _is_vscode_server_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        searchable = self._join_searchable(
            name,
            executable,
            command_line,
            " ".join(args),
        )

        if ".vscode-server" in searchable:
            return True

        if self._basename(executable) == "node" and "vscode" in searchable.lower():
            return True

        return False

    def _is_shell_startup_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        base = self._basename(executable)

        if name == "dircolors" or base == "dircolors":
            return (
                args == ["dircolors", "-b"]
                or command_line == "dircolors -b"
            )

        searchable = self._join_searchable(
            name,
            executable,
            command_line,
            " ".join(args),
        )

        if "lesspipe" not in searchable:
            return False

        return name in {
            "dash",
            "sh",
            "basename",
            "dirname",
        } or base in {
            "dash",
            "sh",
            "basename",
            "dirname",
        }

    def _is_development_git_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        base = self._basename(executable)

        if name != "git" and base != "git":
            return False

        if args == ["git", "config", "--get", "commit.template"]:
            return True

        if args == ["git", "status", "-z", "-uall"]:
            return True

        if args == ["git", "worktree", "list", "--porcelain"]:
            return True

        if len(args) >= 2 and args[0] == "git" and args[1] == "for-each-ref":
            return True

        if len(args) >= 2 and args[0] == "git" and args[1] == "rev-parse":
            return self._is_git_rev_parse_noise(args=args)

        if command_line == "git config --get commit.template":
            return True

        if command_line == "git status -z -uall":
            return True

        if command_line == "git worktree list --porcelain":
            return True

        if command_line.startswith("git for-each-ref "):
            return True

        if command_line.startswith("git rev-parse "):
            return self._is_git_rev_parse_command_noise(command_line=command_line)

        return False

    def _is_git_rev_parse_noise(self, args: list[str]) -> bool:
        known_noise_args = {
            ("git", "rev-parse", "--show-toplevel"),
            ("git", "rev-parse", "--git-dir"),
            ("git", "rev-parse", "--git-common-dir"),
            ("git", "rev-parse", "--show-superproject-working-tree"),
            ("git", "rev-parse", "--is-inside-work-tree"),
        }

        return tuple(args) in known_noise_args

    def _is_git_rev_parse_command_noise(self, command_line: str) -> bool:
        return command_line in {
            "git rev-parse --show-toplevel",
            "git rev-parse --git-dir",
            "git rev-parse --git-common-dir",
            "git rev-parse --show-superproject-working-tree",
            "git rev-parse --is-inside-work-tree",
        }

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

        return False

    def _is_known_sleep_polling_noise(
        self,
        name: str,
        executable: str,
        command_line: str,
        args: list[str],
    ) -> bool:
        base = self._basename(executable)

        if name != "sleep" and base != "sleep":
            return False

        return (
            args == ["sleep", "1"]
            or command_line == "sleep 1"
        )

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

    def _join_searchable(self, *values: str) -> str:
        return " ".join(
            value
            for value in values
            if value
        )