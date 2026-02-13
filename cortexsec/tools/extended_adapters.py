from __future__ import annotations
import shlex
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from cortexsec.tools.base import ToolAdapter

class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    
    def build_command(self, target: str, options: str = "") -> list[str]:
        # Default to JSON output for easier parsing
        base = ["nuclei", "-u", target, "-json-export", "nuclei_output.json", "-silent"]
        if options:
            base.extend(shlex.split(options))
        return base

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        try:
            # Nuclei can output multiple JSON objects separated by newlines in the file
            # But we used -json-export which might be different. 
            # Actually, nuclei often prints JSON to stdout if configured.
            # Let's try to parse stdout first if it looks like JSON
            for line in stdout.splitlines():
                try:
                    data = json.loads(line)
                    findings.append({
                        "type": data.get("info", {}).get("name", "nuclei_finding"),
                        "severity": data.get("info", {}).get("severity", "unknown"),
                        "evidence": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", "")
                    })
                except json.JSONDecodeError:
                    continue
        except Exception:
            pass

        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }

class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    
    def build_command(self, target: str, options: str = "") -> list[str]:
        base = [
            "sqlmap",
            "-u",
            target,
            "--batch",
            "--random-agent",
            "--crawl=1",
            "--forms",
            "--level=1",
            "--risk=1",
            "--technique=BEUSTQ",
        ]
        if options:
            base.extend(shlex.split(options))
        return base

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        if "is vulnerable" in stdout or "is injectable" in stdout:
            findings.append({
                "type": "sql_injection",
                "severity": "Critical",
                "evidence": "sqlmap confirmed vulnerability"
            })
        
        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }

class NiktoAdapter(ToolAdapter):
    name = "nikto"
    
    def build_command(self, target: str, options: str = "") -> list[str]:
        base = ["nikto", "-h", target, "-Tuning", "123b"]
        if options:
            base.extend(shlex.split(options))
        return base

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            if "+ " in line:
                findings.append({
                    "type": "web_server_issue",
                    "evidence": line.strip()
                })
        
        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }

class GobusterAdapter(ToolAdapter):
    name = "gobuster"
    
    def build_command(self, target: str, options: str = "") -> list[str]:
        # Requires a wordlist. Using a common one if available or a small dummy one.
        wordlist = "/usr/share/dirb/wordlists/common.txt"
        base = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q"]
        if options:
            base.extend(shlex.split(options))
        return base

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for line in stdout.splitlines():
            if "(Status: 200)" in line or "(Status: 301)" in line:
                findings.append({
                    "type": "directory_found",
                    "evidence": line.strip()
                })
        
        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }


class FfufAdapter(ToolAdapter):
    name = "ffuf"

    def build_command(self, target: str, options: str = "") -> list[str]:
        wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        base = [
            "ffuf",
            "-u",
            f"{target.rstrip('/')}/FUZZ",
            "-w",
            wordlist,
            "-of",
            "json",
            "-mc",
            "200,204,301,302,307,401,403",
            "-timeout",
            "5",
            "-rate",
            "50",
        ]
        if options:
            base.extend(shlex.split(options))
        return base

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for result in data.get("results", []):
                findings.append(
                    {
                        "type": "ffuf_endpoint_discovery",
                        "severity": "Info",
                        "evidence": f"{result.get('url', '')} (status={result.get('status', 'unknown')}, words={result.get('words', 'unknown')})",
                        "path": result.get("input", {}).get("FUZZ", ""),
                    }
                )
        except json.JSONDecodeError:
            for line in stdout.splitlines():
                normalized = line.strip()
                if normalized and "[Status:" in normalized:
                    findings.append({"type": "ffuf_endpoint_discovery", "severity": "Info", "evidence": normalized})

        return {
            "tool": self.name,
            "target": target,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "status": "ok" if exit_code == 0 else "error",
            "exit_code": exit_code,
            "findings": findings,
            "raw": {"stdout": stdout, "stderr": stderr},
        }
