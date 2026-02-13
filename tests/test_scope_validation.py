import hashlib
import json

from typer.testing import CliRunner

from cortexsec.api.contracts import AssessmentResult
from cortexsec.cli.main import app
from cortexsec.utils.scope_utils import ScopeValidationError, load_scope_file


BASE_SCOPE = {
    "targets": [{"url": "http://localhost:8080", "type": "web"}],
    "exclusions": [{"pattern": "/admin", "reason": "out of engagement"}],
    "timeframe_start": "2026-01-01T00:00:00",
    "timeframe_end": "2026-01-31T23:59:59",
    "client_approval": {
        "approved_by": "CISO",
        "approval_date": "2025-12-15T12:00:00",
        "document_hash": None,
    },
    "version": "1.0",
}


def _scope_with_valid_hash():
    payload = json.loads(json.dumps(BASE_SCOPE))
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["client_approval"]["document_hash"] = hashlib.sha256(canonical).hexdigest()
    return payload


def test_load_scope_file_valid_json_with_hash(tmp_path):
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(_scope_with_valid_hash()), encoding="utf-8")

    scope = load_scope_file(str(scope_path))

    assert scope.targets[0].url == "http://localhost:8080"
    assert scope.client_approval.approved_by == "CISO"


def test_load_scope_file_rejects_hash_mismatch(tmp_path):
    invalid_scope = _scope_with_valid_hash()
    invalid_scope["version"] = "2.0"

    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(invalid_scope), encoding="utf-8")

    try:
        load_scope_file(str(scope_path))
        assert False, "Expected scope hash mismatch to fail"
    except ScopeValidationError as exc:
        assert "integrity check failed" in str(exc)


def test_cli_authorized_mode_requires_scope_file():
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["start", "--target", "http://localhost:8080", "--mode", "authorized"],
    )

    assert result.exit_code == 1
    assert "--scope-file is mandatory" in result.output


def test_cli_accepts_valid_scope_file(monkeypatch, tmp_path):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "\n".join(
            [
                "targets:",
                "  - url: http://localhost:8080",
                "    type: web",
                "exclusions: []",
                "timeframe_start: '2026-01-01T00:00:00'",
                "timeframe_end: '2026-01-31T23:59:59'",
                "client_approval:",
                "  approved_by: CISO",
                "  approval_date: '2025-12-15T12:00:00'",
                "version: '1.0'",
            ]
        ),
        encoding="utf-8",
    )

    captured = {}

    def fake_run(self, request):
        captured["scope_url"] = request.scope.targets[0].url
        return AssessmentResult(
            target=request.target,
            status="ok",
            run_id="test-run",
            findings_count=0,
            risk_level="Low",
            stop_reason="complete",
            telemetry={},
            artifacts={"log": "tests.log"},
        )

    monkeypatch.setattr("cortexsec.cli.main.CliEngine.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "start",
            "--target",
            "http://localhost:8080",
            "--mode",
            "authorized",
            "--scope-file",
            str(scope_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["scope_url"] == "http://localhost:8080"
