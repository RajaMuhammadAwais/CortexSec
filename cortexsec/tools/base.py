from __future__ import annotations

import json
import shlex
import subprocess
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict


class ToolAdapter(ABC):
    name: str
    timeout_seconds: int = 300

    SAFE_MODE_BLOCKED_TOKENS = {
        "--os-shell",
        "--os-pwn",
        "--os-smbrelay",
        "--sql-shell",
        "--sql-file",
        "--file-write",
        "--file-dest",
        "--registry-read",
        "--registry-write",
        "--priv-esc",
        "--tor",
        "--tamper",
        "--flush-session",
        "--drop-set-cookie",
        "--threads",
        "--data",
        "--method",
        "-x",
        "--request-file",
        "--eval",
    }

    @abstractmethod
    def build_command(self, target: str, options: str = "") -> list[str]:
        raise NotImplementedError

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        raise NotImplementedError

    def _check_safe_mode_policy(self, options: str) -> str | None:
        tokens = [token.strip().lower() for token in shlex.split(options or "")]
        for token in tokens:
            if token in self.SAFE_MODE_BLOCKED_TOKENS:
                return token
        return None

    def invoke(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        target = payload.get("target", "")
        options = payload.get("options", "")
        safe_mode = payload.get("safe_mode", True)
        timestamp = datetime.now(timezone.utc).isoformat()

        if safe_mode:
            blocked_token = self._check_safe_mode_policy(options)
            if blocked_token:
                return {
                    "tool": self.name,
                    "target": target,
                    "timestamp_utc": timestamp,
                    "status": "blocked",
                    "error": "safe-mode-policy-blocked",
                    "blocked_option": blocked_token,
                    "raw": {"stdout": "", "stderr": f"Blocked option in safe mode: {blocked_token}"},
                }

        argv = self.build_command(target=target, options=options)

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
            return self.parse_output(proc.stdout, proc.stderr, proc.returncode, target)
        except FileNotFoundError:
            return {
                "tool": self.name,
                "target": target,
                "timestamp_utc": timestamp,
                "status": "error",
                "error": "tool-not-installed",
                "raw": {"stdout": "", "stderr": "command-not-found"},
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "tool": self.name,
                "target": target,
                "timestamp_utc": timestamp,
                "status": "error",
                "error": "tool-timeout",
                "raw": {"stdout": exc.stdout or "", "stderr": exc.stderr or "timeout"},
            }


class ToolManager:
    def __init__(self, adapters: Dict[str, ToolAdapter]):
        self.adapters = {name.lower(): adapter for name, adapter in adapters.items()}

    def _resolve(self, tool_name: str) -> ToolAdapter:
        tool = (tool_name or "").lower().strip()
        if tool not in self.adapters:
            raise ValueError(f"Unsupported tool: {tool}")
        return self.adapters[tool]

    def invoke_json(self, payload_json: str) -> Dict[str, Any]:
        payload = json.loads(payload_json)
        return self.invoke(payload)

    def invoke(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        adapter = self._resolve(payload.get("tool", ""))
        return adapter.invoke(payload)
