import typer
from dotenv import load_dotenv
from rich.console import Console
from typer import Context

from cortexsec.api.contracts import AssessmentRequest
from cortexsec.app.config import AppConfig
from cortexsec.app.logging_config import configure_structured_logging
from cortexsec.core.agent_communication import CommunicationOrchestrator, build_default_agent_team
from cortexsec.engine.cli_engine import CliEngine

load_dotenv()
console = Console()
app = typer.Typer(name="cortexsec", help="CortexSec - Autonomous AI Security Assessment Agent")


def _validate_log_level(value: str) -> str:
    normalized = (value or "basic").lower().strip()
    if normalized not in {"basic", "detailed", "forensic"}:
        raise typer.BadParameter("--log-level must be one of: basic, detailed, forensic")
    return normalized


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
    )


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
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
):
    if mode == "lab" and not (target.startswith("http://localhost") or "127.0.0.1" in target):
        console.print("[bold red]Error: Lab mode only supports localhost targets.[/bold red]")
        raise typer.Exit(code=1)

    if destructive_mode and not pro_user:
        console.print("[bold red]Error:[/bold red] --destructive-mode requires --pro-user.")
        raise typer.Exit(code=1)

    normalized_log_level = _validate_log_level(log_level)

    cfg = AppConfig.from_file_and_env()
    configure_structured_logging(cfg.log_dir)

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
        log_level=normalized_log_level,
        anonymize_logs=anonymize_logs,
    )

    result = CliEngine().run(request)

    if result.status != "ok":
        console.print(f"[bold red]Assessment failed:[/bold red] {result.stop_reason}")
        raise typer.Exit(code=1)

    console.print("\n[bold green]Assessment Complete![/bold green]")
    console.print(f"Target: {result.target}")
    console.print(f"Findings: {result.findings_count}")
    console.print(f"Risk: {result.risk_level}")
    console.print(f"Run ID: {result.run_id}")
    console.print(f"Log file: {result.artifacts.get('log')}")


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
