import hashlib
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from pathlib import Path

UNKNOWN_SHORT_LIVED = "unknown (short-lived process)"
UNKNOWN_PERMISSION = "unknown (permission denied)"
UNKNOWN_UNAVAILABLE = "unknown (proc unavailable)"


@dataclass
class ProcEnrichmentStatus:
    enriched: bool
    command_line_status: str
    executable_status: str
    hash_status: str
    reason: Optional[str] = None


class ProcEnricher:

    def __init__(
        self,
        chunk_size: int = 4096,
        enable_hash_cache: bool = True,
    ) -> None:
        self.chunk_size = int(chunk_size)
        self.enable_hash_cache = enable_hash_cache
        self._hash_cache: Dict[Tuple[int, int, int, int], str] = {}

    def enrich(self, ecs_doc: Dict[str, Any]) -> Dict[str, Any]:
        process = ecs_doc.setdefault("process", {})
        pid = process.get("pid")

        if not isinstance(pid, int) or pid <= 0:
            self._set_status(
                ecs_doc,
                ProcEnrichmentStatus(
                    enriched=False,
                    command_line_status="skipped",
                    executable_status="skipped",
                    hash_status="skipped",
                    reason="missing or invalid process.pid",
                ),
            )
            return ecs_doc

        command_line_status = self._enrich_command_line(pid, process)
        executable_status = self._enrich_executable(pid, process)
        self._correct_process_name_from_executable(ecs_doc, process)
        hash_status = self._enrich_sha256(pid, process)

        enriched = any(
            status == "ok"
            for status in [
                command_line_status,
                executable_status,
                hash_status,
            ]
        )

        reason = self._build_reason(
            command_line_status=command_line_status,
            executable_status=executable_status,
            hash_status=hash_status,
        )

        self._set_status(
            ecs_doc,
            ProcEnrichmentStatus(
                enriched=enriched,
                command_line_status=command_line_status,
                executable_status=executable_status,
                hash_status=hash_status,
                reason=reason,
            ),
        )

        return ecs_doc

    def _enrich_command_line(
        self,
        pid: int,
        process: Dict[str, Any],
    ) -> str:
        try:
            command_line = self._read_cmdline(pid)

            if command_line:
                process["command_line"] = command_line
                return "ok"

            # Nu suprascriem o valoare deja pusă de normalizer.
            process.setdefault("command_line", UNKNOWN_UNAVAILABLE)
            return "empty"

        except FileNotFoundError:
            process.setdefault("command_line", UNKNOWN_SHORT_LIVED)
            return "short_lived"

        except PermissionError:
            process.setdefault("command_line", UNKNOWN_PERMISSION)
            return "permission_denied"

        except OSError:
            process.setdefault("command_line", UNKNOWN_UNAVAILABLE)
            return "os_error"

    def _enrich_executable(
        self,
        pid: int,
        process: Dict[str, Any],
    ) -> str:
        exe_link = f"/proc/{pid}/exe"

        try:
            executable = os.readlink(exe_link)

            if executable:
                process["executable"] = executable
                return "ok"

            process.setdefault("executable", UNKNOWN_UNAVAILABLE)
            return "empty"

        except FileNotFoundError:
            process.setdefault("executable", UNKNOWN_SHORT_LIVED)
            return "short_lived"

        except PermissionError:
            process.setdefault("executable", UNKNOWN_PERMISSION)
            return "permission_denied"

        except OSError:
            process.setdefault("executable", UNKNOWN_UNAVAILABLE)
            return "os_error"

    def _enrich_sha256(
        self,
        pid: int,
        process: Dict[str, Any],
    ) -> str:
        exe_link = f"/proc/{pid}/exe"

        try:
            sha256_value = self._sha256_file_with_cache(exe_link)

            if not sha256_value:
                return "empty"

            process.setdefault("hash", {})
            process["hash"]["sha256"] = sha256_value

            return "ok"

        except FileNotFoundError:
            return "short_lived"

        except PermissionError:
            return "permission_denied"

        except OSError:
            return "os_error"

    def _read_cmdline(self, pid: int) -> Optional[str]:
        path = f"/proc/{pid}/cmdline"

        with open(path, "rb") as file:
            raw = file.read()

        if not raw:
            return None

        parts = [
            part.decode("utf-8", errors="replace")
            for part in raw.split(b"\x00")
            if part
        ]

        command_line = " ".join(parts).strip()
        return command_line or None

    def _sha256_file_with_cache(self, path: str) -> str:
        stat_result = os.stat(path)

        cache_key = (
            stat_result.st_dev,
            stat_result.st_ino,
            stat_result.st_size,
            stat_result.st_mtime_ns,
        )

        if self.enable_hash_cache and cache_key in self._hash_cache:
            return self._hash_cache[cache_key]

        sha256_value = self._sha256_file(path)

        if self.enable_hash_cache:
            self._hash_cache[cache_key] = sha256_value

        return sha256_value

    def _sha256_file(self, path: str) -> str:
        digest = hashlib.sha256()

        with open(path, "rb") as file:
            while True:
                chunk = file.read(self.chunk_size)

                if not chunk:
                    break

                digest.update(chunk)

        return digest.hexdigest()

    def _build_reason(
        self,
        command_line_status: str,
        executable_status: str,
        hash_status: str,
    ) -> Optional[str]:
        failed = []

        if command_line_status not in {"ok", "empty"}:
            failed.append(f"command_line={command_line_status}")

        if executable_status not in {"ok", "empty"}:
            failed.append(f"executable={executable_status}")

        if hash_status not in {"ok", "empty"}:
            failed.append(f"hash={hash_status}")

        if not failed:
            return None

        return "; ".join(failed)

    def _set_status(
        self,
        ecs_doc: Dict[str, Any],
        status: ProcEnrichmentStatus,
    ) -> None:
        edr = ecs_doc.setdefault("edr", {})
        enrichment = edr.setdefault("enrichment", {})

        enrichment["proc"] = {
            "enriched": status.enriched,
            "command_line_status": status.command_line_status,
            "executable_status": status.executable_status,
            "hash_status": status.hash_status,
        }

        if status.reason:
            enrichment["proc"]["reason"] = status.reason
    
    def _correct_process_name_from_executable(
        self,
        ecs_doc: Dict[str, Any],
        process: Dict[str, Any],
    ) -> None:
        executable = process.get("executable")

        if not isinstance(executable, str):
            return

        if executable.startswith("unknown"):
            return

        real_name = Path(executable).name

        if not real_name:
            return

        old_name = process.get("name")

        if old_name == real_name:
            return

        edr = ecs_doc.setdefault("edr", {})
        enrichment = edr.setdefault("enrichment", {})
        proc = enrichment.setdefault("proc", {})

        proc["original_process_name"] = old_name
        proc["process_name_corrected"] = True

        process["name"] = real_name