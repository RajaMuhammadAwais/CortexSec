import typer
from rich.console import Console
from dotenv import load_dotenv
from cortexsec.llm.factory import create_llm
from cortexsec.core.agent import PentestContext
from cortexsec.core.planner import SupervisorAgent
from cortexsec.agents.recon import ReconAgent
from cortexsec.agents.attack_surface_agent import AttackSurfaceAgent
from cortexsec.agents.payload_agent import PayloadAgent
from cortexsec.agents.vuln_analysis import VulnAnalysisAgent
from cortexsec.agents.reasoning_agent import ReasoningAgent
from cortexsec.agents.exploitability_agent import ExploitabilityAgent
from cortexsec.agents.risk_agent import RiskAgent
from cortexsec.agents.attack_simulation import AttackSimulationAgent
from cortexsec.agents.memory_agent import MemoryAgent
from cortexsec.agents.report_agent import ReportAgent

load_dotenv()
console = Console()
app = typer.Typer(name="cortexsec", help="CortexSec - Autonomous AI Security Assessment Agent")


@app.command()
def start(
    target: str = typer.Option(..., "--target", "-t", help="Target URL or IP"),
    mode: str = typer.Option("lab", "--mode", "-m", help="Assessment mode (lab/authorized)"),
    provider: str = typer.Option("openai", "--provider", help="LLM provider: openai/claude/gemini"),
    model: str = typer.Option("", "--model", help="LLM model name (optional)"),
    api_key: str = typer.Option(None, "--api-key", help="LLM API Key"),
    max_cycles: int = typer.Option(5, "--max-cycles", help="Maximum autonomous reasoning cycles"),
    confidence_threshold: float = typer.Option(0.8, "--confidence-threshold", help="Stop when avg finding confidence reaches this"),
    coverage_threshold: float = typer.Option(0.8, "--coverage-threshold", help="Stop when coverage score reaches this"),
    causal_threshold: float = typer.Option(1.0, "--causal-threshold", help="Stop when attack-graph causal completeness reaches this"),
    exploitability_threshold: float = typer.Option(0.75, "--exploitability-threshold", help="Minimum exploitability confidence required across reachable findings"),
    min_stable_cycles: int = typer.Option(1, "--min-stable-cycles", help="Require this many cycles with no new findings before stopping"),
    continuous_improvement: bool = typer.Option(False, "--continuous-improvement", help="Keep refining even after convergence by extending extra cycles"),
    max_auto_extensions: int = typer.Option(2, "--max-auto-extensions", help="Maximum extra cycles when continuous improvement is enabled"),
    retry_failed_agents: int = typer.Option(1, "--retry-failed-agents", help="Retries per agent when a cycle step fails"),
    vuln_refinement_rounds: int = typer.Option(2, "--vuln-refinement-rounds", help="Extra research-style refinement rounds in vulnerability analysis"),
    live_attack_graph: bool = typer.Option(False, "--live-attack-graph", help="Render live attack-graph progress per cycle"),
    pro_user: bool = typer.Option(False, "--pro-user", help="Enable pro workflow features"),
    destructive_mode: bool = typer.Option(False, "--destructive-mode", help="Pro-only: generate destructive test plans (execution is blocked by safety policy)"),
):
    """Start a fully autonomous security assessment."""
    console.print(f"[bold blue]Starting AI Security Assessment for:[/bold blue] {target}")
    console.print(f"[bold yellow]Mode:[/bold yellow] {mode}")

    if mode == "lab" and not (target.startswith("http://localhost") or "127.0.0.1" in target):
        console.print("[bold red]Error: Lab mode only supports localhost targets.[/bold red]")
        raise typer.Exit(code=1)


    if destructive_mode and not pro_user:
        console.print("[bold red]Error:[/bold red] --destructive-mode requires --pro-user.")
        raise typer.Exit(code=1)

    if destructive_mode:
        console.print("[bold yellow]Safety:[/bold yellow] Destructive mode is planning-only in CortexSec. No destructive payloads are executed automatically.")

    try:
        llm = create_llm(provider=provider, model=model, api_key=api_key)
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {str(e)}")
        raise typer.Exit(code=1)

    agents = [
        ReconAgent(llm),
        AttackSurfaceAgent(llm),
        PayloadAgent(llm),
        VulnAnalysisAgent(llm, refinement_rounds=vuln_refinement_rounds),
        ReasoningAgent(llm),
        ExploitabilityAgent(llm),
        RiskAgent(llm),
        AttackSimulationAgent(llm),
        MemoryAgent(llm),
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
        continuous_improvement=continuous_improvement,
        pro_user=pro_user,
        destructive_mode=destructive_mode,
    )
    final_context = supervisor.run(context)

    console.print("\n[bold green]Assessment Complete![/bold green]")
    console.print(f"Total Findings: {len(final_context.findings)}")
    console.print(f"Risk Level: {final_context.risk_summary.get('level', 'Unknown')}")
    console.print(f"Coverage Score: {final_context.assessment_metrics.get('coverage_score', 0.0)}")
    console.print(f"Average Confidence: {final_context.assessment_metrics.get('avg_confidence', 0.0)}")
    console.print(f"Causal Completeness: {final_context.assessment_metrics.get('causal_completeness', 0.0)}")
    console.print(f"Min Exploitability Confidence: {final_context.assessment_metrics.get('min_exploitability_confidence', 0.0)}")
    console.print(f"Orchestrator Reward (last): {final_context.orchestrator_learning.get('last_reward', 0.0)}")
    console.print(
        f"Reachable Findings Analyzed: "
        f"{final_context.assessment_metrics.get('analyzed_reachable_findings', 0)}/"
        f"{final_context.assessment_metrics.get('reachable_findings', 0)}"
    )
    console.print(f"Stop Reason: {final_context.stop_reason}")
    console.print("Check the 'reports' directory for the final report.")


if __name__ == "__main__":
    app()
