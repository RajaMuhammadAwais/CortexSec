from __future__ import annotations

import shlex
import subprocess
import time
from datetime import datetime, timezone
from typing import Dict, Any, List

from pydantic import BaseModel, Field

from cortexsec.core.agent import PentestContext


class PlannerOutput(BaseModel):
    """Planner contract defining the next hypothesis and safe action."""

    hypothesis: str
    objective: str
    action: str
    success_criteria: str


class ExecutorOutput(BaseModel):
    """Executor contract carrying command provenance and result."""

    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timestamp_utc: str


class CriticOutput(BaseModel):
    """Critic contract to accept/reject evidence and guide next steps."""

    verdict: str = Field(description="accepted | needs-followup | rejected")
    confidence_delta: float
    rationale: str


class ThoughtActionObservation(BaseModel):
    """Structured run trace entry for autonomous execution."""

    thought: str
    action: Dict[str, Any]
    observation: Dict[str, Any]


class SafetyGate:
    """Policy checks required before command execution."""

    @staticmethod
    def evaluate(context: PentestContext, command: str) -> Dict[str, Any]:
        if context.mode != "authorized":
            return {"allowed": False, "reason": "mode-not-authorized"}

        if context.destructive_mode:
            return {"allowed": False, "reason": "destructive-mode-enabled"}

        cmd_lower = command.lower()
        blocked_tokens = [" rm ", " mkfs", "shutdown", "reboot", " dd "]
        padded = f" {cmd_lower} "
        if any(token in padded for token in blocked_tokens):
            return {"allowed": False, "reason": "destructive-command-pattern"}

        return {"allowed": True, "reason": "ok"}


class CommandExecutor:
    """Safe command execution wrapper with provenance fields."""

    def __init__(self, timeout_seconds: int = 15):
        self.timeout_seconds = timeout_seconds

    def run(self, context: PentestContext, command: str) -> ExecutorOutput:
        gate = SafetyGate.evaluate(context, command)
        now = datetime.now(timezone.utc).isoformat()
        if not gate["allowed"]:
            return ExecutorOutput(
                command=command,
                exit_code=126,
                stdout="",
                stderr=f"blocked-by-policy:{gate['reason']}",
                duration_ms=0,
                timestamp_utc=now,
            )

        started = time.perf_counter()
        try:
            argv = shlex.split(command)
            if not argv:
                return ExecutorOutput(
                    command=command,
                    exit_code=2,
                    stdout="",
                    stderr="invalid-command:empty",
                    duration_ms=0,
                    timestamp_utc=now,
                )

            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
            duration = int((time.perf_counter() - started) * 1000)
            return ExecutorOutput(
                command=command,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=duration,
                timestamp_utc=now,
            )
        except subprocess.TimeoutExpired as exc:
            duration = int((time.perf_counter() - started) * 1000)
            return ExecutorOutput(
                command=command,
                exit_code=124,
                stdout=exc.stdout or "",
                stderr="timeout",
                duration_ms=duration,
                timestamp_utc=now,
            )
        except FileNotFoundError:
            duration = int((time.perf_counter() - started) * 1000)
            return ExecutorOutput(
                command=command,
                exit_code=127,
                stdout="",
                stderr="command-not-found",
                duration_ms=duration,
                timestamp_utc=now,
            )


class AutonomyLoop:
    """Minimal planner→executor→critic loop implementation."""

    def __init__(self, executor: CommandExecutor | None = None, max_steps: int = 3):
        self.executor = executor or CommandExecutor()
        self.max_steps = max_steps

    def run(self, context: PentestContext, plans: List[PlannerOutput]) -> PentestContext:
        steps = plans[: self.max_steps]
        for plan in steps:
            result = self.executor.run(context, plan.action)
            verdict = "accepted" if result.exit_code == 0 else "needs-followup"
            critic = CriticOutput(
                verdict=verdict,
                confidence_delta=0.1 if verdict == "accepted" else -0.05,
                rationale=f"command exit_code={result.exit_code}",
            )
            trace = ThoughtActionObservation(
                thought=f"Hypothesis: {plan.hypothesis}",
                action={"objective": plan.objective, "command": plan.action},
                observation={
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "timestamp_utc": result.timestamp_utc,
                    "critic_verdict": critic.verdict,
                    "confidence_delta": critic.confidence_delta,
                },
            )
            context.history.append({"agent": "AutonomyLoop", **trace.model_dump()})

        return context
