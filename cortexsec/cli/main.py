import time

import typer
from dotenv import load_dotenv
from rich.console import Console
from typer import Context

from cortexsec.agents.attack_simulation import AttackSimulationAgent
from cortexsec.agents.attack_surface_agent import AttackSurfaceAgent
from cortexsec.agents.autonomous_exploit_agent import AutonomousExploitationAgent
from cortexsec.agents.browser_autonomous_agent import BrowserAutonomousAgent
from cortexsec.agents.competitive_planning_agent import CompetitivePlanningAgent
from cortexsec.agents.exploitability_agent import ExploitabilityAgent
from cortexsec.agents.memory_agent import MemoryAgent
from cortexsec.agents.network_analyzer import NetworkAnalyzer
from cortexsec.agents.payload_agent import PayloadAgent
from cortexsec.agents.reasoning_agent import ReasoningAgent
from cortexsec.agents.recon import ReconAgent
from cortexsec.agents.remediation_advisor import RemediationAdvisor
from cortexsec.agents.report_agent import ReportAgent
from cortexsec.agents.risk_agent import RiskAgent
from cortexsec.agents.vuln_analysis import VulnAnalysisAgent
from cortexsec.agents.web_app_scanner import WebAppScannerAgent
from cortexsec.agents.zero_day_detector import ZeroDayDetector
from cortexsec.core.agent import PentestContext
from cortexsec.core.agent_communication import CommunicationOrchestrator, build_default_agent_team
from cortexsec.core.audit import AuditConfig, AuditLogger
from cortexsec.core.planner import SupervisorAgent
from cortexsec.core.sandbox import DockerSandboxRunner
from cortexsec.llm.factory import create_llm
from cortexsec.tools import NmapAdapter, ToolManager, ZapAdapter

load_dotenv()
console = Console()
app = typer.Typer(name="cortexsec", help="CortexSec - Autonomous AI Security Assessment Agent")


def _execute_tooling(target: str, logger: AuditLogger) -> dict:
    manager = ToolManager({"nmap": NmapAdapter(), "zap": ZapAdapter()})
    requests = [
        {"tool": "nmap", "target": target, "options": "-sV -Pn"},
        {"tool": "zap", "target": target, "options": ""},
    ]
    reports = []
    for payload in requests:
        logger.log("tool_command", payload)
        reports.append(manager.invoke(payload))
    return {"target": target, "generated_at": time.time(), "tools": reports}


def _validate_log_level(log_level: str) -> str:
    normalized = (log_level or "basic").lower().strip()
    if normalized not in {"basic", "detailed", "forensic"}:
        raise typer.BadParameter("--log-level must be one of: basic, detailed, forensic")
    return normalized


@app.callback(invoke_without_command=True)
def main(
    ctx: Context,
    target: str = typer.Option(None, "--target", "-t", help="Target URL or IP"),
    mode: str = typer.Option("lab", "--mode", "-m"),
    provider: str = typer.Option("openai", "--provider"),
    llm_provider: str = typer.Option("", "--llm-provider"),
    model: str = typer.Option("", "--model"),
    model_path: str = typer.Option("", "--model-path"),
    api_key: str = typer.Option(None, "--api-key"),
    max_cycles: int = typer.Option(5, "--max-cycles"),
    confidence_threshold: float = typer.Option(0.8, "--confidence-threshold"),
    coverage_threshold: float = typer.Option(0.8, "--coverage-threshold"),
    causal_threshold: float = typer.Option(1.0, "--causal-threshold"),
    exploitability_threshold: float = typer.Option(0.75, "--exploitability-threshold"),
    min_stable_cycles: int = typer.Option(1, "--min-stable-cycles"),
    continuous_improvement: bool = typer.Option(False, "--continuous-improvement"),
    require_findings_before_stop: bool = typer.Option(False, "--require-findings-before-stop"),
    max_no_finding_extensions: int = typer.Option(3, "--max-no-finding-extensions"),
    max_auto_extensions: int = typer.Option(2, "--max-auto-extensions"),
    retry_failed_agents: int = typer.Option(1, "--retry-failed-agents"),
    vuln_refinement_rounds: int = typer.Option(2, "--vuln-refinement-rounds"),
    live_attack_graph: bool = typer.Option(False, "--live-attack-graph"),
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
    sandboxed: bool = typer.Option(False, "--sandboxed"),
    sandbox_image: str = typer.Option("cortexsec/sandbox:latest", "--sandbox-image"),
    enable_external_tools: bool = typer.Option(False, "--enable-external-tools", help="Run Nmap and ZAP adapters"),
    log_level: str = typer.Option("basic", "--log-level"),
    anonymize_logs: bool = typer.Option(False, "--anonymize-logs"),
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
        confidence_threshold=confidence_threshold,
        coverage_threshold=coverage_threshold,
        causal_threshold=causal_threshold,
        exploitability_threshold=exploitability_threshold,
        min_stable_cycles=min_stable_cycles,
        continuous_improvement=continuous_improvement,
        require_findings_before_stop=require_findings_before_stop,
        max_no_finding_extensions=max_no_finding_extensions,
        max_auto_extensions=max_auto_extensions,
        retry_failed_agents=retry_failed_agents,
        vuln_refinement_rounds=vuln_refinement_rounds,
        live_attack_graph=live_attack_graph,
        pro_user=pro_user,
        destructive_mode=destructive_mode,
        sandboxed=sandboxed,
        sandbox_image=sandbox_image,
        enable_external_tools=enable_external_tools,
        log_level=log_level,
        anonymize_logs=anonymize_logs,
    )


@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP"),
    mode: str = typer.Option("lab", "--mode", "-m", help="Assessment mode (lab/authorized)"),
    provider: str = typer.Option("openai", "--provider", help="LLM provider: openai/claude/gemini/deepseek/ollama/local-gguf"),
    llm_provider: str = typer.Option("", "--llm-provider", help="Alias to --provider"),
    model: str = typer.Option("", "--model", help="LLM model name (optional)"),
    model_path: str = typer.Option("", "--model-path", help="Path to local GGUF model"),
    api_key: str = typer.Option(None, "--api-key", help="LLM API Key"),
    max_cycles: int = typer.Option(5, "--max-cycles", help="Maximum autonomous reasoning cycles"),
    confidence_threshold: float = typer.Option(0.8, "--confidence-threshold"),
    coverage_threshold: float = typer.Option(0.8, "--coverage-threshold"),
    causal_threshold: float = typer.Option(1.0, "--causal-threshold"),
    exploitability_threshold: float = typer.Option(0.75, "--exploitability-threshold"),
    min_stable_cycles: int = typer.Option(1, "--min-stable-cycles"),
    continuous_improvement: bool = typer.Option(False, "--continuous-improvement"),
    require_findings_before_stop: bool = typer.Option(False, "--require-findings-before-stop"),
    max_no_finding_extensions: int = typer.Option(3, "--max-no-finding-extensions"),
    max_auto_extensions: int = typer.Option(2, "--max-auto-extensions"),
    retry_failed_agents: int = typer.Option(1, "--retry-failed-agents"),
    vuln_refinement_rounds: int = typer.Option(2, "--vuln-refinement-rounds"),
    live_attack_graph: bool = typer.Option(False, "--live-attack-graph"),
    pro_user: bool = typer.Option(False, "--pro-user"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode"),
    sandboxed: bool = typer.Option(False, "--sandboxed", help="Run in Docker sandbox"),
    sandbox_image: str = typer.Option("cortexsec/sandbox:latest", "--sandbox-image"),
    enable_external_tools: bool = typer.Option(False, "--enable-external-tools", help="Run Nmap and ZAP adapters"),
    log_level: str = typer.Option("basic", "--log-level", help="basic|detailed|forensic"),
    anonymize_logs: bool = typer.Option(False, "--anonymize-logs"),
):
    provider = llm_provider or provider
    normalized_log_level = _validate_log_level(log_level)

    logger = AuditLogger(AuditConfig(log_level=normalized_log_level, anonymize=anonymize_logs))
    logger.log("run_start", {"target": target, "mode": mode, "provider": provider, "sandboxed": sandboxed})

    if mode == "lab" and not (target.startswith("http://localhost") or "127.0.0.1" in target):
        console.print("[bold red]Error: Lab mode only supports localhost targets.[/bold red]")
        raise typer.Exit(code=1)

    if sandboxed:
        sandbox = DockerSandboxRunner(image=sandbox_image, workspace="/workspace", host_workspace=".")
        probe = sandbox.run("cat /etc/passwd")
        logger.log("trace", {"sandbox_probe": probe.__dict__})
        if probe.exit_code == 0:
            console.print("[bold red]Sandbox validation failed: /etc/passwd was readable[/bold red]")
            raise typer.Exit(code=1)

    if destructive_mode and not pro_user:
        console.print("[bold red]Error:[/bold red] --destructive-mode requires --pro-user.")
        raise typer.Exit(code=1)

    try:
        llm = create_llm(provider=provider, model=model, api_key=api_key, model_path=model_path)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

    logger.prompt_hash(f"provider={provider}|model={model}|target={target}")
    external_report = _execute_tooling(target=target, logger=logger) if enable_external_tools else {}

    agents = [
        ReconAgent(llm),
        AttackSurfaceAgent(llm),
        WebAppScannerAgent(llm),
        BrowserAutonomousAgent(llm),
        PayloadAgent(llm),
        VulnAnalysisAgent(llm, refinement_rounds=vuln_refinement_rounds),
        NetworkAnalyzer(llm),
        AutonomousExploitationAgent(llm),
        ZeroDayDetector(llm),
        ReasoningAgent(llm),
        ExploitabilityAgent(llm),
        RiskAgent(llm),
        AttackSimulationAgent(llm),
        MemoryAgent(llm),
        CompetitivePlanningAgent(llm),
        RemediationAdvisor(llm),
        ReportAgent(llm),
    ]

    supervisor = SupervisorAgent(
        llm,
        agents,
        max_cycles=max_cycles,
        confidence_threshold=confidence_threshold,
        coverage_threshold=coverage_threshold,
        causal_threshold=causal_threshold,
        exploitability_threshold=exploitability_threshold,
        min_stable_cycles=min_stable_cycles,
        max_auto_extensions=max_auto_extensions,
        retry_failed_agents=retry_failed_agents,
        live_attack_graph=live_attack_graph,
    )

    context = PentestContext(
        target=target,
        mode=mode,
        recon_data={"external_tool_report": external_report} if external_report else {},
        continuous_improvement=continuous_improvement,
        require_findings_before_stop=require_findings_before_stop,
        max_no_finding_extensions=max_no_finding_extensions,
        pro_user=pro_user,
        destructive_mode=destructive_mode,
    )
    logger.log("decision", {"decision": "supervisor_run", "risk_score": context.risk_summary.get("score", 0)})
    final_context = supervisor.run(context)

    logger.log("risk_score", {"risk_summary": final_context.risk_summary})
    logger.log("run_end", {"total_findings": len(final_context.findings), "stop_reason": final_context.stop_reason})

    console.print("\n[bold green]Assessment Complete![/bold green]")
    console.print(f"Total Findings: {len(final_context.findings)}")
    console.print(f"Risk Level: {final_context.risk_summary.get('level', 'Unknown')}")
    console.print(f"Forensic log: {logger.log_path}")


@app.command("agent-chat")
def agent_chat(
    prompt: str = typer.Option(..., "--prompt", "-p", help="Task prompt for the agent team"),
    context_id: str = typer.Option("session-1", "--context-id", help="Conversation context identifier"),
    max_turns: int = typer.Option(12, "--max-turns", help="Maximum turn-based exchanges"),
):
    orchestrator = CommunicationOrchestrator(build_default_agent_team())
    console.print("[bold blue]Starting multi-agent communication demo[/bold blue]")
    orchestrator.run_session(user_prompt=prompt, context_id=context_id, max_turns=max_turns)


if __name__ == "__main__":
    app()
