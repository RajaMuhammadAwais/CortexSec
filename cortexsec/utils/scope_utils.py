from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import yaml

from cortexsec.api.contracts import ScopeFile


class ScopeValidationError(ValueError):
    """Raised when scope file loading or validation fails."""


def _parse_scope_payload(path: Path) -> Dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    try:
        if suffix in {".yaml", ".yml"}:
            parsed = yaml.safe_load(raw_text)
        else:
            parsed = json.loads(raw_text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ScopeValidationError(f"Scope file parse error: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ScopeValidationError("Scope file must contain a JSON/YAML object at the root")

    return parsed


def _hash_scope_payload(payload: Dict[str, Any], algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    hasher.update(canonical)
    return hasher.hexdigest()


def validate_scope_integrity(scope_payload: Dict[str, Any]) -> None:
    client_approval = scope_payload.get("client_approval")
    if not isinstance(client_approval, dict):
        raise ScopeValidationError("client_approval must be an object")

    expected_hash = client_approval.get("document_hash")
    if not expected_hash:
        return

    payload_for_hash = json.loads(json.dumps(scope_payload))
    payload_for_hash["client_approval"]["document_hash"] = None

    observed_hash = _hash_scope_payload(payload_for_hash, algorithm="sha256")
    if observed_hash != expected_hash:
        raise ScopeValidationError(
            "Scope file integrity check failed: document_hash does not match canonical payload"
        )


def load_scope_file(scope_file_path: str) -> ScopeFile:
    path = Path(scope_file_path)
    if not path.exists():
        raise ScopeValidationError(f"Scope file not found: {scope_file_path}")

    payload = _parse_scope_payload(path)
    validate_scope_integrity(payload)

    try:
        return ScopeFile.model_validate(payload)
    except Exception as exc:
        raise ScopeValidationError(f"Scope schema validation failed: {exc}") from exc
