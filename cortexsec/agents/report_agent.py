from cortexsec.core.agent import BaseAgent, PentestContext
import os


class ReportAgent(BaseAgent):
    """Agent responsible for generating the final report."""

    def __init__(self, llm):
        super().__init__("ReportAgent", llm)

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Generating professional consultant-grade report...")

        findings_data = []
        for f in context.findings:
            findings_data.append(
                {
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "cvss_score": f.cvss_score,
                    "description": f.description,
                    "mitigation": f.mitigation,
                    "owasp": f.owasp_mapping,
                    "mitre": f.mitre_mapping,
                    "reachable": f.reachable,
                    "analyzed": f.analyzed,
                    "impact_summary": f.impact_summary,
                    "exploitability_summary": f.exploitability_summary,
                }
            )

        report_prompt = f"""
        Generate a professional autonomous security assessment report for {context.target}.

        Findings Data:
        {findings_data}

        Attack Surface Model:
        {context.attack_surface}

        Attack Graph:
        {context.attack_graph}

        Risk Summary:
        {context.risk_summary}

        Exploitability Assessment:
        {context.exploitability_assessment}

        Scientific Analysis:
        {context.scientific_analysis}

        Safe Attack Simulation Playbooks:
        {context.attack_simulation}

        Payload Injection Test Results (real-world, non-destructive):
        {context.payload_tests}

        Agent Memory:
        {context.memory}

        Orchestrator Learning State:
        {context.orchestrator_learning}

        Operating Mode Flags:
        pro_user={context.pro_user}
        destructive_mode={context.destructive_mode}

        Assessment Metrics and Stop Condition:
        metrics={context.assessment_metrics}
        stop_reason={context.stop_reason}

        Include sections:
        1) Executive Summary
        2) Autonomous Methodology (multi-agent reasoning and coordination)
        3) Coverage, Confidence, Causal-Completeness, and Exploitability-Confidence Termination Criteria
        4) Attack-Surface + Attack-Graph Causal Analysis
        5) Detailed Findings with OWASP, CVSS, MITRE mapping
        6) Real-World Exploitability and Business-Impact Evaluation (non-destructive only)
        7) Orchestrator Learning Summary (reward, strategy shifts, convergence)
        8) Pentest-Style Real-World Payload Analysis (hypothesis, observed behavior, risk, false-positive checks)
        9) Scientific Confidence Calibration (hypothesis quality, signal strength, false-positive risk)
        10) Prioritized Remediation Roadmap
        11) Destructive-Mode Plan (if enabled): authorization prerequisites, rollback, blast-radius controls
        12) Conclusion

        Keep it explainable, concise, and professional markdown.
        """

        report_md = self.llm.generate(report_prompt, system_prompt="You are a professional cybersecurity consultant.")

        report_path = "reports/pentest_report.md"
        os.makedirs("reports", exist_ok=True)
        with open(report_path, "w") as f:
            f.write(report_md)

        self.log(f"Report generated successfully at {report_path}")
        return context
