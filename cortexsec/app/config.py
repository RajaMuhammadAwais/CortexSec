from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import yaml


@dataclass
class AppConfig:
    """Environment/file driven runtime configuration."""

    default_provider: str = "openai"
    default_model: str = ""
    log_dir: str = "logs"
    reports_dir: str = "reports"

    @classmethod
    def from_file_and_env(cls, path: str = "cortexsec.yaml") -> "AppConfig":
        file_data: Dict[str, Any] = {}
        cfg_path = Path(path)
        if cfg_path.exists():
            file_data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}

        return cls(
            default_provider=os.getenv("CORTEXSEC_DEFAULT_PROVIDER", file_data.get("default_provider", "openai")),
            default_model=os.getenv("CORTEXSEC_DEFAULT_MODEL", file_data.get("default_model", "")),
            log_dir=os.getenv("CORTEXSEC_LOG_DIR", file_data.get("log_dir", "logs")),
            reports_dir=os.getenv("CORTEXSEC_REPORTS_DIR", file_data.get("reports_dir", "reports")),
        )
