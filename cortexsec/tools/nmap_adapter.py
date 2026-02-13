from __future__ import annotations

import shlex
from datetime import datetime, timezone
from typing import Any, Dict, List

from cortexsec.tools.base import ToolAdapter


class NmapAdapter(ToolAdapter):
    name = "nmap"

    def build_command(self, target: str, options: str = "") -> list[str]:
        # Enforce safe defaults for nmap
        safe_defaults = ["-sV", "-Pn", "--open", "--max-rate", "100"]
        opt_tokens = shlex.split(options) if options else safe_defaults
        
        # Filter out potentially invasive scripts if any
        filtered_tokens = [t for t in opt_tokens if not t.startswith("--script=")]
        if not any(t.startswith("-s") for t in filtered_tokens):
            filtered_tokens.append("-sV")
            
        return ["nmap", *filtered_tokens, target]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            line = line.strip()
            if "/tcp" in line and "open" in line:
                findings.append({"type": "open_port", "evidence": line})

        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }
