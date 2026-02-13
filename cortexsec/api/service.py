from __future__ import annotations

import logging
from typing import Dict, List

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
from cortexsec.api.contracts import AssessmentRequest, AssessmentResult
from cortexsec.core.agent import PentestContext
from cortexsec.core.audit import AuditConfig, AuditLogger
from cortexsec.core.planner import SupervisorAgent
from cortexsec.core.sandbox import DockerSandboxRunner
from cortexsec.llm.factory import create_llm
from cortexsec.plugins import (
    GobusterPlugin,
    FfufPlugin,
    NiktoPlugin,
    NmapPlugin,
    NucleiPlugin,
    PluginContext,
    PluginRegistry,
    SqlmapPlugin,
    ZapPlugin,
)
from cortexsec.telemetry.benchmark import BenchmarkRecorder


class AssessmentService:
    """Application service: single orchestration API for CLI and GUI."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("cortexsec.runtime")
        self.plugins = PluginRegistry()
        self.plugins.register(NmapPlugin())
        self.plugins.register(ZapPlugin())
        self.plugins.register(NucleiPlugin())
        self.plugins.register(SqlmapPlugin())
        self.plugins.register(NiktoPlugin())
        self.plugins.register(GobusterPlugin())
        self.plugins.register(FfufPlugin())

    def _run_plugins(self, request: AssessmentRequest, recorder: BenchmarkRecorder) -> Dict[str, dict]:
        if not request.enable_external_tools:
            return {}

        plugin_ids: List[str] = request.plugins or [
            "scanner.nmap",
            "scanner.zap",
            "scanner.nuclei",
            "scanner.sqlmap",
            "scanner.nikto",
            "scanner.gobuster",
            "scanner.ffuf",
        ]
        reports = self.plugins.run_many(plugin_ids, PluginContext(request=request))
        recorder.note("plugins", plugin_ids)
        recorder.incr("plugin_runs", len(plugin_ids))
        return reports

    def execute(self, request: AssessmentRequest) -> AssessmentResult:
        recorder = BenchmarkRecorder()
        audit = AuditLogger(AuditConfig(log_level=request.log_level, anonymize=request.anonymize_logs))
        audit.log("run_start", {"target": request.target, "mode": request.mode, "provider": request.provider})

        if request.sandboxed:
            probe = DockerSandboxRunner(image=request.sandbox_image, workspace="/workspace", host_workspace=".").run(
                "cat /etc/passwd"
            )
            audit.log("trace", {"sandbox_probe": probe.__dict__})
            if probe.exit_code == 0:
                return AssessmentResult(
                    target=request.target,
                    status="failed",
                    run_id=audit.run_id,
                    findings_count=0,
                    risk_level="Unknown",
                    stop_reason="sandbox-validation-failed",
                    telemetry=recorder.snapshot(),
                    artifacts={"log": str(audit.log_path)},
                )

        llm = create_llm(
            provider=request.provider,
            model=request.model,
            api_key=request.api_key,
            model_path=request.model_path,
        )

        plugin_reports = self._run_plugins(request, recorder)
        audit.log("decision", {"decision": "plugin_execution", "plugin_count": len(plugin_reports)})

        agents = [
            ReconAgent(llm),
            AttackSurfaceAgent(llm),
            WebAppScannerAgent(llm),
            BrowserAutonomousAgent(llm),
            PayloadAgent(llm),
            VulnAnalysisAgent(llm),
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

        supervisor = SupervisorAgent(llm, agents, max_cycles=request.max_cycles)

        context = PentestContext(
            target=request.target,
            mode=request.mode,
            recon_data={"external_tool_report": plugin_reports} if plugin_reports else {},
            scope=request.scope,
        )
        out = supervisor.run(context)

        recorder.incr("findings", len(out.findings))
        recorder.note("risk_level", out.risk_summary.get("level", "Unknown"))
        telemetry = recorder.snapshot()

        audit.log("run_end", {"total_findings": len(out.findings), "stop_reason": out.stop_reason})

        return AssessmentResult(
            target=request.target,
            status="ok",
            run_id=audit.run_id,
            findings_count=len(out.findings),
            risk_level=out.risk_summary.get("level", "Unknown"),
            stop_reason=out.stop_reason,
            telemetry=telemetry,
            artifacts={"log": str(audit.log_path), "plugin_reports": plugin_reports},
        )
