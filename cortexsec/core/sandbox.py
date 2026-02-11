from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


@dataclass
class SandboxExecutionResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str


class DockerSandboxRunner:
    """Run commands in a least-privilege Docker sandbox."""

    def __init__(
        self,
        image: str = "cortexsec/sandbox:latest",
        workspace: str = "/workspace",
        host_workspace: str | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        self.image = image
        self.workspace = workspace
        self.host_workspace = host_workspace or os.getcwd()
        self.timeout_seconds = timeout_seconds

    def _validate_command(self, command: str) -> Dict[str, str]:
        if not command.strip():
            return {"allowed": "false", "reason": "empty-command"}

        lowered = command.lower()
        if "/etc/passwd" in lowered:
            return {"allowed": "false", "reason": "path-access-denied"}

        try:
            tokens = shlex.split(command)
        except ValueError:
            return {"allowed": "false", "reason": "invalid-command"}

        for token in tokens:
            if token.startswith("/") and not token.startswith(self.workspace):
                return {"allowed": "false", "reason": "path-outside-workspace"}

        return {"allowed": "true", "reason": "ok"}

    def build_docker_command(self, command: str) -> List[str]:
        host_workspace = str(Path(self.host_workspace).resolve())
        return [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "-u",
            "10001:10001",
            "-v",
            f"{host_workspace}:{self.workspace}:rw",
            "-w",
            self.workspace,
            self.image,
            "sh",
            "-lc",
            command,
        ]

    def run(self, command: str) -> SandboxExecutionResult:
        decision = self._validate_command(command)
        if decision["allowed"] != "true":
            return SandboxExecutionResult(
                command=command,
                exit_code=126,
                stdout="",
                stderr=f"blocked-by-sandbox:{decision['reason']}",
            )

        docker_cmd = self.build_docker_command(command)
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            return SandboxExecutionResult(
                command=command,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except FileNotFoundError:
            return SandboxExecutionResult(
                command=command,
                exit_code=127,
                stdout="",
                stderr="docker-not-installed",
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxExecutionResult(
                command=command,
                exit_code=124,
                stdout=exc.stdout or "",
                stderr="sandbox-timeout",
            )
