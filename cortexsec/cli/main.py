import json
import time
from pathlib import Path

import typer
from dotenv import load_dotenv
from rich.console import Console
from typer import Context

from cortexsec.api.contracts import AssessmentRequest
from cortexsec.app.config import AppConfig
from cortexsec.app.logging_config import configure_structured_logging
from cortexsec.core.agent_communication import CommunicationOrchestrator, build_default_agent_team
from cortexsec.engine.cli_engine import CliEngine
from cortexsec.utils.scope_utils import ScopeValidationError, load_scope_file

load_dotenv()
console = Console()
app = typer.Typer(name="cortexsec", help="CortexSec - Autonomous AI Security Assessment Agent")


def _validate_log_level(value: str) -> str:
    normalized = (value or "basic").lower().strip()
    if normalized not in {"basic", "detailed", "forensic"}:
        raise typer.BadParameter("--log-level must be one of: basic, detailed, forensic")
    return normalized


def _validate_target_for_mode(target: str, mode: str) -> None:
    if mode == "lab" and not (target.startswith("http://localhost") or "127.0.0.1" in target):
        console.print("[bold red]Error: Lab mode only supports localhost targets.[/bold red]")
        raise typer.Exit(code=1)


def _load_targets_file(path: str) -> list[str]:
    raw = Path(path).read_text(encoding="utf-8").strip()
    if not raw:
        raise typer.BadParameter("--targets-file is empty")

    if path.endswith(".json"):
        payload = json.loads(raw)
        if not isinstance(payload, list) or not all(isinstance(item, str) and item.strip() for item in payload):
            raise typer.BadParameter("JSON targets file must be a non-empty array of strings")
        return [item.strip() for item in payload]

    targets: list[str] = []
    for line in raw.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        targets.append(value)

    if not targets:
        raise typer.BadParameter("--targets-file does not contain any valid targets")
    return targets


def _build_request(
    target: str,
    mode: str,
    provider: str,
    llm_provider: str,
    model: str,
    model_path: str,
    api_key: str | None,
    max_cycles: int,
    sandboxed: bool,
    sandbox_image: str,
    enable_external_tools: bool,
    log_level: str,
    anonymize_logs: bool,
    safe_mode: bool,
    scope_file: str | None,
    scope,
) -> AssessmentRequest:
    return AssessmentRequest(
        target=target,
        mode=mode,
        provider=llm_provider or provider,
        model=model,
        model_path=model_path,
        api_key=api_key,
        max_cycles=max_cycles,
        sandboxed=sandboxed,
        sandbox_image=sandbox_image,
        enable_external_tools=enable_external_tools,
        log_level=log_level,
        anonymize_logs=anonymize_logs,
        safe_mode=safe_mode,
        scope_file_path=scope_file,
        scope=scope,
    )




def _run_single_assessment(
    engine: CliEngine,
    target: str,
    mode: str,
    provider: str,
    llm_provider: str,
    model: str,
    model_path: str,
    api_key: str | None,
    max_cycles: int,
    sandboxed: bool,
    sandbox_image: str,
    enable_external_tools: bool,
    log_level: str,
    anonymize_logs: bool,
    safe_mode: bool,
    scope_file: str | None,
    validated_scope,
):
    _validate_target_for_mode(target, mode)
    request = _build_request(
        target=target,
        mode=mode,
        provider=provider,
        llm_provider=llm_provider,
        model=model,
        model_path=model_path,
        api_key=api_key,
        max_cycles=max_cycles,
        sandboxed=sandboxed,
        sandbox_image=sandbox_image,
        enable_external_tools=enable_external_tools,
        log_level=log_level,
        anonymize_logs=anonymize_logs,
        safe_mode=safe_mode,
        scope_file=scope_file,
        scope=validated_scope,
    )
    return engine.run(request)


def _prepare_runtime(
    mode: str,
    scope_file: str | None,
    log_level: str,
    destructive_mode: bool,
    pro_user: bool,
    safe_mode: bool,
):
    if destructive_mode and not pro_user:
        console.print("[bold red]Error:[/bold red] --destructive-mode requires --pro-user.")
        raise typer.Exit(code=1)

    if mode == "authorized" and not scope_file:
        console.print("[bold red]HALT:[/bold red] --scope-file is mandatory in authorized mode. Escalate to security lead.")
        raise typer.Exit(code=1)

    validated_scope = None
    if scope_file:
        try:
            validated_scope = load_scope_file(scope_file)
        except ScopeValidationError as exc:
            console.print(f"[bold red]HALT:[/bold red] Invalid scope file: {exc}. Escalate to security lead.")
            raise typer.Exit(code=1)

    final_safe_mode = False if destructive_mode else safe_mode
    normalized_log_level = _validate_log_level(log_level)

    cfg = AppConfig.from_file_and_env()
    configure_structured_logging(cfg.log_dir)

    return validated_scope, normalized_log_level, final_safe_mode


@app.callback(invoke_without_command=True)
def main(
    ctx: Context,
    target: str = typer.Option(None, "--target", "-t", help="Target URL or IP"),
    mode: str = typer.Option("lab", "--mode", "-m", help="Assessment mode (lab/authorized)"),
    provider: str = typer.Option("openai", "--provider", help="LLM provider"),
    llm_provider: str = typer.Option("", "--llm-provider", help="Alias to --provider"),
    model: str = typer.Option("", "--model", help="LLM model name"),
    model_path: str = typer.Option("", "--model-path", help="Path to local GGUF model"),
    api_key: str = typer.Option(None, "--api-key", help="LLM API key"),
    max_cycles: int = typer.Option(5, "--max-cycles"),
    sandboxed: bool = typer.Option(False, "--sandboxed", help="Run with docker sandbox guard"),
    sandbox_image: str = typer.Option("cortexsec/sandbox:latest", "--sandbox-image"),
    enable_external_tools: bool = typer.Option(False, "--enable-external-tools"),
    log_level: str = typer.Option("basic", "--log-level", help="basic|detailed|forensic"),
    anonymize_logs: bool = typer.Option(False, "--anonymize-logs"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--unsafe-mode", help="Restrict external tool options to non-destructive checks"),
    scope_file: str = typer.Option(None, "--scope-file", help="Path to authorized assessment scope JSON/YAML"),
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
):
    if ctx.invoked_subcommand is not None or target is None:
        return

    start(
        target=target,
        mode=mode,
        provider=provider,
        llm_provider=llm_provider,
        model=model,
        model_path=model_path,
        api_key=api_key,
        max_cycles=max_cycles,
        sandboxed=sandboxed,
        sandbox_image=sandbox_image,
        enable_external_tools=enable_external_tools,
        log_level=log_level,
        anonymize_logs=anonymize_logs,
        safe_mode=safe_mode,
        scope_file=scope_file,
        pro_user=pro_user,
        destructive_mode=destructive_mode,
    )


@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP"),
    mode: str = typer.Option("lab", "--mode", "-m", help="Assessment mode (lab/authorized)"),
    provider: str = typer.Option("openai", "--provider", help="LLM provider"),
    llm_provider: str = typer.Option("", "--llm-provider", help="Alias to --provider"),
    model: str = typer.Option("", "--model", help="LLM model name"),
    model_path: str = typer.Option("", "--model-path", help="Path to local GGUF model"),
    api_key: str = typer.Option(None, "--api-key", help="LLM API key"),
    max_cycles: int = typer.Option(5, "--max-cycles"),
    sandboxed: bool = typer.Option(False, "--sandboxed", help="Run with docker sandbox guard"),
    sandbox_image: str = typer.Option("cortexsec/sandbox:latest", "--sandbox-image"),
    enable_external_tools: bool = typer.Option(False, "--enable-external-tools"),
    log_level: str = typer.Option("basic", "--log-level", help="basic|detailed|forensic"),
    anonymize_logs: bool = typer.Option(False, "--anonymize-logs"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--unsafe-mode", help="Restrict external tool options to non-destructive checks"),
    scope_file: str = typer.Option(None, "--scope-file", help="Path to authorized assessment scope JSON/YAML"),
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
):
    _validate_target_for_mode(target, mode)
    validated_scope, normalized_log_level, final_safe_mode = _prepare_runtime(
        mode=mode,
        scope_file=scope_file,
        log_level=log_level,
        destructive_mode=destructive_mode,
        pro_user=pro_user,
        safe_mode=safe_mode,
    )

    result = _run_single_assessment(
        engine=CliEngine(),
        target=target,
        mode=mode,
        provider=provider,
        llm_provider=llm_provider,
        model=model,
        model_path=model_path,
        api_key=api_key,
        max_cycles=max_cycles,
        sandboxed=sandboxed,
        sandbox_image=sandbox_image,
        enable_external_tools=enable_external_tools,
        log_level=normalized_log_level,
        anonymize_logs=anonymize_logs,
        safe_mode=final_safe_mode,
        scope_file=scope_file,
        validated_scope=validated_scope,
    )

    if result.status != "ok":
        console.print(f"[bold red]Assessment failed:[/bold red] {result.stop_reason}")
        raise typer.Exit(code=1)

    console.print("\n[bold green]Assessment Complete![/bold green]")
    console.print(f"Target: {result.target}")
    console.print(f"Findings: {result.findings_count}")
    console.print(f"Risk: {result.risk_level}")
    console.print(f"Run ID: {result.run_id}")
    console.print(f"Log file: {result.artifacts.get('log')}")


@app.command("batch-start")
def batch_start(
    targets_file: str = typer.Option(..., "--targets-file", help="Path to targets file (.txt lines or .json array)"),
    mode: str = typer.Option("lab", "--mode", "-m", help="Assessment mode (lab/authorized)"),
    provider: str = typer.Option("openai", "--provider", help="LLM provider"),
    llm_provider: str = typer.Option("", "--llm-provider", help="Alias to --provider"),
    model: str = typer.Option("", "--model", help="LLM model name"),
    model_path: str = typer.Option("", "--model-path", help="Path to local GGUF model"),
    api_key: str = typer.Option(None, "--api-key", help="LLM API key"),
    max_cycles: int = typer.Option(5, "--max-cycles"),
    sandboxed: bool = typer.Option(False, "--sandboxed", help="Run with docker sandbox guard"),
    sandbox_image: str = typer.Option("cortexsec/sandbox:latest", "--sandbox-image"),
    enable_external_tools: bool = typer.Option(False, "--enable-external-tools"),
    log_level: str = typer.Option("basic", "--log-level", help="basic|detailed|forensic"),
    anonymize_logs: bool = typer.Option(False, "--anonymize-logs"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--unsafe-mode", help="Restrict external tool options to non-destructive checks"),
    scope_file: str = typer.Option(None, "--scope-file", help="Path to authorized assessment scope JSON/YAML"),
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
):
    targets = _load_targets_file(targets_file)
    validated_scope, normalized_log_level, final_safe_mode = _prepare_runtime(
        mode=mode,
        scope_file=scope_file,
        log_level=log_level,
        destructive_mode=destructive_mode,
        pro_user=pro_user,
        safe_mode=safe_mode,
    )

    engine = CliEngine()
    results = []
    for target in targets:
        result = _run_single_assessment(
            engine=engine,
            target=target,
            mode=mode,
            provider=provider,
            llm_provider=llm_provider,
            model=model,
            model_path=model_path,
            api_key=api_key,
            max_cycles=max_cycles,
            sandboxed=sandboxed,
            sandbox_image=sandbox_image,
            enable_external_tools=enable_external_tools,
            log_level=normalized_log_level,
            anonymize_logs=anonymize_logs,
            safe_mode=final_safe_mode,
            scope_file=scope_file,
            validated_scope=validated_scope,
        )
        results.append(result)

    success_count = len([r for r in results if r.status == "ok"])
    failure_count = len(results) - success_count

    console.print("\n[bold green]Batch Assessment Complete![/bold green]")
    console.print(f"Total Targets: {len(results)}")
    console.print(f"Successful: {success_count}")
    console.print(f"Failed: {failure_count}")

    for result in results:
        console.print(
            f"- {result.target} | status={result.status} | findings={result.findings_count} | risk={result.risk_level}"
        )

    if failure_count > 0:
        raise typer.Exit(code=1)


@app.command("schedule-start")
def schedule_start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP"),
    mode: str = typer.Option("lab", "--mode", "-m", help="Assessment mode (lab/authorized)"),
    interval_seconds: int = typer.Option(300, "--interval-seconds", min=1, help="Delay between scheduled runs in seconds"),
    runs: int = typer.Option(1, "--runs", min=1, help="How many times to execute the assessment"),
    provider: str = typer.Option("openai", "--provider", help="LLM provider"),
    llm_provider: str = typer.Option("", "--llm-provider", help="Alias to --provider"),
    model: str = typer.Option("", "--model", help="LLM model name"),
    model_path: str = typer.Option("", "--model-path", help="Path to local GGUF model"),
    api_key: str = typer.Option(None, "--api-key", help="LLM API key"),
    max_cycles: int = typer.Option(5, "--max-cycles"),
    sandboxed: bool = typer.Option(False, "--sandboxed", help="Run with docker sandbox guard"),
    sandbox_image: str = typer.Option("cortexsec/sandbox:latest", "--sandbox-image"),
    enable_external_tools: bool = typer.Option(False, "--enable-external-tools"),
    log_level: str = typer.Option("basic", "--log-level", help="basic|detailed|forensic"),
    anonymize_logs: bool = typer.Option(False, "--anonymize-logs"),
    safe_mode: bool = typer.Option(True, "--safe-mode/--unsafe-mode", help="Restrict external tool options to non-destructive checks"),
    scope_file: str = typer.Option(None, "--scope-file", help="Path to authorized assessment scope JSON/YAML"),
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
):
    validated_scope, normalized_log_level, final_safe_mode = _prepare_runtime(
        mode=mode,
        scope_file=scope_file,
        log_level=log_level,
        destructive_mode=destructive_mode,
        pro_user=pro_user,
        safe_mode=safe_mode,
    )

    engine = CliEngine()
    results = []
    console.print(f"[bold blue]Scheduled assessment started:[/bold blue] target={target} runs={runs} interval={interval_seconds}s")

    for run_index in range(1, runs + 1):
        console.print(f"[cyan]Run {run_index}/{runs}[/cyan] executing...")
        result = _run_single_assessment(
            engine=engine,
            target=target,
            mode=mode,
            provider=provider,
            llm_provider=llm_provider,
            model=model,
            model_path=model_path,
            api_key=api_key,
            max_cycles=max_cycles,
            sandboxed=sandboxed,
            sandbox_image=sandbox_image,
            enable_external_tools=enable_external_tools,
            log_level=normalized_log_level,
            anonymize_logs=anonymize_logs,
            safe_mode=final_safe_mode,
            scope_file=scope_file,
            validated_scope=validated_scope,
        )
        results.append(result)

        if run_index < runs:
            console.print(f"[cyan]Waiting {interval_seconds}s before next run...[/cyan]")
            time.sleep(interval_seconds)

    success_count = len([r for r in results if r.status == "ok"])
    failure_count = len(results) - success_count
    console.print("\n[bold green]Scheduled Assessment Complete![/bold green]")
    console.print(f"Total Runs: {len(results)}")
    console.print(f"Successful: {success_count}")
    console.print(f"Failed: {failure_count}")

    if failure_count > 0:
        raise typer.Exit(code=1)


@app.command("agent-chat")
def agent_chat(
    prompt: str = typer.Option(..., "--prompt", "-p", help="Task prompt for the agent team"),
    context_id: str = typer.Option("session-1", "--context-id", help="Conversation context identifier"),
    max_turns: int = typer.Option(12, "--max-turns", help="Maximum turn-based exchanges"),
):
    orchestrator = CommunicationOrchestrator(build_default_agent_team())
    console.print("[bold blue]Starting multi-agent communication demo[/bold blue]")
    orchestrator.run_session(user_prompt=prompt, context_id=context_id, max_turns=max_turns)


@app.command("gui")
def launch_gui():
    """Launch thin GUI wrapper over the same shared API service."""
    from cortexsec.gui.tk_app import CortexSecGuiApp

    CortexSecGuiApp().start()


if __name__ == "__main__":
    app()
