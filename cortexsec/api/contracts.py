from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScopeTarget(BaseModel):
    """Single authorized target entry from a scope file."""

    url: str
    type: str = "web"


class ScopeExclusion(BaseModel):
    """Pattern that must be excluded from any assessment activity."""

    pattern: str
    reason: Optional[str] = None


class ScopeClientApproval(BaseModel):
    """Client approval metadata for legal and audit traceability."""

    approved_by: str
    approval_date: datetime
    document_hash: Optional[str] = None


class ScopeFile(BaseModel):
    """Validated assessment scope contract consumed by CLI and runtime."""

    targets: List[ScopeTarget]
    exclusions: List[ScopeExclusion] = Field(default_factory=list)
    timeframe_start: datetime
    timeframe_end: datetime
    client_approval: ScopeClientApproval
    version: str = "1.0"


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
    safe_mode: bool = True
    scope_file_path: Optional[str] = None
    scope: Optional[ScopeFile] = None


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
