from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AssessmentRequest:
    """Shared API request used by CLI and GUI wrappers."""

    target: str
    mode: str = "lab"
    provider: str = "openai"
    model: str = ""
    model_path: str = ""
    api_key: Optional[str] = None
    max_cycles: int = 5
    sandboxed: bool = False
    sandbox_image: str = "cortexsec/sandbox:latest"
    enable_external_tools: bool = False
    log_level: str = "basic"
    anonymize_logs: bool = False
    plugins: List[str] = field(default_factory=list)


@dataclass
class AssessmentResult:
    """Portable result envelope for API consumers."""

    target: str
    status: str
    run_id: str
    findings_count: int
    risk_level: str
    stop_reason: str
    telemetry: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)
