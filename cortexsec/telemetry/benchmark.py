from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class BenchmarkRecorder:
    """Telemetry stub for community benchmark and rollout analytics."""

    run_started: float = field(default_factory=time.perf_counter)
    counters: Dict[str, int] = field(default_factory=dict)
    annotations: Dict[str, Any] = field(default_factory=dict)

    def incr(self, key: str, amount: int = 1) -> None:
        self.counters[key] = self.counters.get(key, 0) + amount

    def note(self, key: str, value: Any) -> None:
        self.annotations[key] = value

    def snapshot(self) -> Dict[str, Any]:
        duration_ms = int((time.perf_counter() - self.run_started) * 1000)
        return {
            "duration_ms": duration_ms,
            "counters": dict(self.counters),
            "annotations": dict(self.annotations),
        }
