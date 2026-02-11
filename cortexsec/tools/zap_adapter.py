from __future__ import annotations

import shlex
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List

from cortexsec.tools.base import ToolAdapter


class ZapAdapter(ToolAdapter):
    name = "zap"

    def build_command(self, target: str, options: str = "") -> list[str]:
        base = ["zaproxy", "-cmd", "-quickurl", target, "-quickprogress"]
        if options:
            base.extend(shlex.split(options))
        return base

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            normalized = line.strip().lower()
            if any(keyword in normalized for keyword in ["alert", "risk", "warning"]):
                findings.append({"type": "web_alert", "evidence": line.strip()})

        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }
