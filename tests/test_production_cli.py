from cortexsec.api.contracts import AssessmentResult
from typer.testing import CliRunner

from cortexsec.cli.main import app


def test_cli_rejects_invalid_log_level():
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "start",
            "--target",
            "http://localhost:8080",
            "--mode",
            "lab",
            "--log-level",
            "invalid",
        ],
    )
    assert result.exit_code == 2
    assert "--log-level must be one of" in result.output


def test_cli_blocks_lab_mode_non_localhost_without_subcommand():
    runner = CliRunner()
    result = runner.invoke(app, ["--target", "https://example.com", "--mode", "lab"])
    assert result.exit_code == 1
    assert "Lab mode only supports localhost targets" in result.output


def test_cli_destructive_mode_forces_safe_mode_off(monkeypatch):
    runner = CliRunner()
    captured = {}

    def fake_run(self, request):
        captured["safe_mode"] = request.safe_mode
        return AssessmentResult(
            target=request.target,
            status="ok",
            run_id="test-run",
            findings_count=0,
            risk_level="Low",
            stop_reason="done",
            telemetry={},
            artifacts={"log": "tests.log"},
        )

    monkeypatch.setattr("cortexsec.cli.main.CliEngine.run", fake_run)

    result = runner.invoke(
        app,
        [
            "start",
            "--target",
            "http://localhost:8080",
            "--mode",
            "lab",
            "--pro-user",
            "--destructive-mode",
        ],
    )

    assert result.exit_code == 0
    assert captured["safe_mode"] is False


def test_cli_batch_start_runs_all_targets(tmp_path, monkeypatch):
    runner = CliRunner()
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("http://localhost:8080\nhttp://127.0.0.1:9000\n", encoding="utf-8")

    captured = []

    def fake_run(self, request):
        captured.append(request.target)
        return AssessmentResult(
            target=request.target,
            status="ok",
            run_id=f"run-{len(captured)}",
            findings_count=1,
            risk_level="Low",
            stop_reason="done",
            telemetry={},
            artifacts={"log": "tests.log"},
        )

    monkeypatch.setattr("cortexsec.cli.main.CliEngine.run", fake_run)

    result = runner.invoke(
        app,
        [
            "batch-start",
            "--targets-file",
            str(targets_file),
            "--mode",
            "lab",
        ],
    )

    assert result.exit_code == 0
    assert captured == ["http://localhost:8080", "http://127.0.0.1:9000"]
    assert "Batch Assessment Complete" in result.output


def test_cli_batch_start_json_targets_rejects_invalid_payload(tmp_path):
    runner = CliRunner()
    targets_file = tmp_path / "targets.json"
    targets_file.write_text('{"target": "http://localhost:8080"}', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "batch-start",
            "--targets-file",
            str(targets_file),
            "--mode",
            "lab",
        ],
    )

    assert result.exit_code == 2
    assert "JSON targets file must be a non-empty array of strings" in result.output


def test_cli_schedule_start_runs_requested_count(monkeypatch):
    runner = CliRunner()
    captured = []

    def fake_run(self, request):
        captured.append(request.target)
        return AssessmentResult(
            target=request.target,
            status="ok",
            run_id=f"run-{len(captured)}",
            findings_count=0,
            risk_level="Low",
            stop_reason="done",
            telemetry={},
            artifacts={"log": "tests.log"},
        )

    monkeypatch.setattr("cortexsec.cli.main.CliEngine.run", fake_run)
    monkeypatch.setattr("cortexsec.cli.main.time.sleep", lambda _seconds: None)

    result = runner.invoke(
        app,
        [
            "schedule-start",
            "--target",
            "http://localhost:8080",
            "--mode",
            "lab",
            "--runs",
            "2",
            "--interval-seconds",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert captured == ["http://localhost:8080", "http://localhost:8080"]
    assert "Scheduled Assessment Complete" in result.output


def test_cli_schedule_start_propagates_failures(monkeypatch):
    runner = CliRunner()
    calls = {"n": 0}

    def fake_run(self, request):
        calls["n"] += 1
        status = "failed" if calls["n"] == 2 else "ok"
        return AssessmentResult(
            target=request.target,
            status=status,
            run_id=f"run-{calls['n']}",
            findings_count=0,
            risk_level="Low",
            stop_reason="done",
            telemetry={},
            artifacts={"log": "tests.log"},
        )

    monkeypatch.setattr("cortexsec.cli.main.CliEngine.run", fake_run)
    monkeypatch.setattr("cortexsec.cli.main.time.sleep", lambda _seconds: None)

    result = runner.invoke(
        app,
        [
            "schedule-start",
            "--target",
            "http://localhost:8080",
            "--mode",
            "lab",
            "--runs",
            "2",
            "--interval-seconds",
            "1",
        ],
    )

    assert result.exit_code == 1
