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
