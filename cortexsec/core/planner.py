from typing import List
from cortexsec.core.agent import BaseAgent, PentestContext
from cortexsec.llm.base import BaseLLM
from rich.progress import Progress, SpinnerColumn, TextColumn


class SupervisorAgent(BaseAgent):
    """High-level orchestrator with hierarchical reinforcement-style strategy updates."""

    def __init__(
        self,
        llm: BaseLLM,
        agents: List[BaseAgent],
        max_cycles: int = 6,
        confidence_threshold: float = 0.8,
        coverage_threshold: float = 0.8,
        causal_threshold: float = 1.0,
        exploitability_threshold: float = 0.75,
        min_stable_cycles: int = 1,
        max_auto_extensions: int = 2,
        retry_failed_agents: int = 1,
    ):
        super().__init__("Supervisor", llm)
        self.agents = {agent.name: agent for agent in agents}
        self.max_cycles = max_cycles
        self.confidence_threshold = confidence_threshold
        self.coverage_threshold = coverage_threshold
        self.causal_threshold = causal_threshold
        self.exploitability_threshold = exploitability_threshold
        self.min_stable_cycles = min_stable_cycles
        self.max_auto_extensions = max(0, max_auto_extensions)
        self.retry_failed_agents = max(0, retry_failed_agents)

    def _ensure_learning_state(self, context: PentestContext):
        if not context.orchestrator_learning:
            context.orchestrator_learning = {
                "policy_scores": {"discovery": 1.0, "validation": 1.0, "convergence": 1.0},
                "last_reward": 0.0,
                "reward_history": [],
            }

    def _choose_focus(self, context: PentestContext) -> str:
        self._ensure_learning_state(context)
        scores = context.orchestrator_learning["policy_scores"]
        return max(scores, key=scores.get)

    def _workflow_for_focus(self, focus: str):
        base = [
            ("Reconnaissance", "ReconAgent"),
            ("Attack Surface Modeling", "AttackSurfaceAgent"),
            ("Payload Injection Testing", "PayloadAgent"),
            ("Vulnerability Analysis", "VulnAnalysisAgent"),
            ("Attack-Graph Reasoning", "ReasoningAgent"),
            ("Exploitability Analysis", "ExploitabilityAgent"),
            ("Scientific Validation", "ScientistAgent"),
            ("Risk Assessment", "RiskAgent"),
            ("Attack Simulation Planning", "AttackSimulationAgent"),
            ("Memory Update", "MemoryAgent"),
        ]
        if focus == "discovery":
            return base
        if focus == "validation":
            return [base[2], base[3], base[4], base[5], base[6], base[7], base[9]]
        return [base[4], base[5], base[6], base[7], base[9]]

    def _update_metrics(self, context: PentestContext, cycle: int, stable_cycles: int, prev_metrics: dict):
        findings = context.findings
        avg_confidence = sum([f.confidence for f in findings]) / len(findings) if findings else 0.0

        header_count = len(context.recon_data.get("raw", {}).get("headers", {}))
        surface_points = len(context.attack_surface.get("entry_points", [])) + len(context.attack_surface.get("exposed_services", []))
        coverage_score = min(1.0, (header_count / 12.0) + (len(findings) / 10.0) + (surface_points / 8.0))

        reachable = len([f for f in findings if f.reachable])
        analyzed = len([f for f in findings if f.reachable and f.analyzed])
        analyzed_ratio = round((analyzed / reachable), 3) if reachable else 1.0

        causal_completeness = float(context.attack_graph.get("causal_completeness", 0.0))
        confirmed_paths = int(context.attack_graph.get("confirmed_paths", 0))

        avg_exp_conf = float(context.exploitability_assessment.get("avg_exploitability_confidence", 0.0))
        min_exp_conf = float(context.exploitability_assessment.get("min_exploitability_confidence", 0.0))

        info_gain = len(findings) - int(prev_metrics.get("findings_count", 0))
        confidence_gain = round(avg_confidence - float(prev_metrics.get("avg_confidence", 0.0)), 3)
        uncertainty_reduction = round((1 - float(prev_metrics.get("avg_confidence", 0.0))) - (1 - avg_confidence), 3)

        context.assessment_metrics = {
            "cycle": cycle,
            "avg_confidence": round(avg_confidence, 3),
            "coverage_score": round(coverage_score, 3),
            "findings_count": len(findings),
            "reachable_findings": reachable,
            "analyzed_reachable_findings": analyzed,
            "analyzed_ratio": analyzed_ratio,
            "causal_completeness": causal_completeness,
            "confirmed_paths": confirmed_paths,
            "avg_exploitability_confidence": round(avg_exp_conf, 3),
            "min_exploitability_confidence": round(min_exp_conf, 3),
            "info_gain": info_gain,
            "confidence_gain": confidence_gain,
            "uncertainty_reduction": uncertainty_reduction,
            "stable_cycles_without_new_findings": stable_cycles,
            "confidence_threshold": self.confidence_threshold,
            "coverage_threshold": self.coverage_threshold,
            "causal_threshold": self.causal_threshold,
            "exploitability_threshold": self.exploitability_threshold,
            "min_stable_cycles": self.min_stable_cycles,
        }

    def _update_learning(self, context: PentestContext, focus: str):
        self._ensure_learning_state(context)
        m = context.assessment_metrics

        reward = (
            (0.2 * max(m["info_gain"], 0))
            + (0.4 * max(m["confidence_gain"], 0.0))
            + (0.3 * max(m["uncertainty_reduction"], 0.0))
            + (0.1 * (m["confirmed_paths"] / max(m["reachable_findings"], 1)))
        )

        policy_scores = context.orchestrator_learning["policy_scores"]
        policy_scores[focus] = round((policy_scores.get(focus, 1.0) * 0.9) + reward, 4)
        context.orchestrator_learning["last_reward"] = round(reward, 4)
        context.orchestrator_learning["reward_history"].append(round(reward, 4))
        context.orchestrator_learning["reward_history"] = context.orchestrator_learning["reward_history"][-20:]

    def run(self, context: PentestContext) -> PentestContext:
        self.log(f"Starting autonomous closed-loop orchestration for {context.target}")

        stable_cycles = 0
        previous_count = 0
        prev_metrics = {}
        dynamic_max_cycles = self.max_cycles
        auto_extensions_used = 0

        context.memory.setdefault("agent_recovery_log", [])

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            cycle = 1
            while cycle <= dynamic_max_cycles:
                focus = self._choose_focus(context)
                workflow = self._workflow_for_focus(focus)
                self.log(f"Cycle {cycle}/{dynamic_max_cycles} started with focus={focus}")

                for description, agent_name in workflow:
                    if agent_name not in self.agents:
                        continue

                    task_id = progress.add_task(f"[cyan]Cycle {cycle}: {description}...", total=1)

                    run_ok = False
                    last_error = ""
                    for attempt in range(self.retry_failed_agents + 1):
                        try:
                            context = self.agents[agent_name].run(context)
                            run_ok = True
                            if attempt > 0:
                                context.memory["agent_recovery_log"].append(
                                    {
                                        "cycle": cycle,
                                        "agent": agent_name,
                                        "status": "recovered",
                                        "attempt": attempt + 1,
                                    }
                                )
                            break
                        except Exception as e:
                            last_error = str(e)
                            self.log(f"Error in {agent_name} (attempt {attempt + 1}): {last_error}")

                    if run_ok:
                        progress.update(task_id, completed=1, description=f"[green]Cycle {cycle}: {description} Complete")
                    else:
                        context.memory["agent_recovery_log"].append(
                            {
                                "cycle": cycle,
                                "agent": agent_name,
                                "status": "failed",
                                "attempts": self.retry_failed_agents + 1,
                                "error": last_error,
                            }
                        )
                        progress.update(task_id, completed=1, description=f"[red]Cycle {cycle}: {description} Failed")

                current_count = len(context.findings)
                stable_cycles = stable_cycles + 1 if current_count == previous_count else 0
                previous_count = current_count

                self._update_metrics(context, cycle, stable_cycles, prev_metrics)
                self._update_learning(context, focus)
                prev_metrics = dict(context.assessment_metrics)
                m = context.assessment_metrics

                converged = (
                    m["avg_confidence"] >= self.confidence_threshold
                    and m["coverage_score"] >= self.coverage_threshold
                    and m["causal_completeness"] >= self.causal_threshold
                    and m["analyzed_ratio"] >= 1.0
                    and m["min_exploitability_confidence"] >= self.exploitability_threshold
                    and m["stable_cycles_without_new_findings"] >= self.min_stable_cycles
                )

                if converged and context.continuous_improvement and auto_extensions_used < self.max_auto_extensions:
                    auto_extensions_used += 1
                    dynamic_max_cycles += 1
                    self.log(
                        f"Converged at cycle {cycle}, extending for extra research cycle "
                        f"({auto_extensions_used}/{self.max_auto_extensions})."
                    )
                elif converged and not context.continuous_improvement:
                    context.stop_reason = (
                        f"Stopped at cycle {cycle}: security knowledge converged with all reachable findings analyzed "
                        f"(confidence={m['avg_confidence']}, coverage={m['coverage_score']}, causal={m['causal_completeness']}, "
                        f"exploitability={m['min_exploitability_confidence']}, analyzed={m['analyzed_reachable_findings']}/{m['reachable_findings']})."
                    )
                    break

                cycle += 1

            if not context.stop_reason:
                context.stop_reason = (
                    f"Stopped after max cycles ({dynamic_max_cycles}) with best available evidence. "
                    "Increase --max-cycles for deeper convergence if needed."
                )

        if "ReportAgent" in self.agents:
            context = self.agents["ReportAgent"].run(context)

        self.log(f"Pentest workflow completed. {context.stop_reason}")
        return context
