from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional


@dataclass
class AuditConfig:
    log_level: str = "basic"
    anonymize: bool = False
    log_dir: str = "logs"


class AuditLogger:
    """JSONL forensic audit logger with deterministic replay support."""

    def __init__(self, config: AuditConfig, run_id: Optional[str] = None) -> None:
        self.config = config
        self.run_id = run_id or str(uuid.uuid4())
        self.log_path = Path(config.log_dir) / f"{self.run_id}.jsonl"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _anonymize(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.anonymize:
            return payload
        scrubbed = dict(payload)
        for key in ("target", "command", "prompt", "decision"):
            if key in scrubbed and isinstance(scrubbed[key], str):
                scrubbed[key] = hashlib.sha256(scrubbed[key].encode("utf-8")).hexdigest()
        return scrubbed

    def _should_log(self, event_type: str) -> bool:
        allowed = {
            "basic": {"run_start", "run_end", "decision", "tool_command"},
            "detailed": {"run_start", "run_end", "decision", "tool_command", "risk_score", "prompt_hash"},
            "forensic": {"run_start", "run_end", "decision", "tool_command", "risk_score", "prompt_hash", "trace"},
        }
        level = self.config.log_level.lower()
        return event_type in allowed.get(level, allowed["basic"])

    def log(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self._should_log(event_type):
            return

        record = {
            "timestamp_utc": self._now(),
            "run_id": self.run_id,
            "event_type": event_type,
            "payload": self._anonymize(payload),
        }
        with self.log_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(record, sort_keys=True) + "\n")

    def prompt_hash(self, prompt: str) -> str:
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        self.log("prompt_hash", {"hash": digest})
        return digest

    @staticmethod
    def replay(path: str) -> Iterable[Dict[str, Any]]:
        with Path(path).open("r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if line:
                    yield json.loads(line)
