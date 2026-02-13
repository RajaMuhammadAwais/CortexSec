from cortexsec.core.agent import BaseAgent, PentestContext
import os
from cortexsec.agents.real_world_guidance import real_world_prompt


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
                    "cwe": f.cwe_id,
                    "compliance": f.compliance_tags,
                    "reachable": f.reachable,
                    "analyzed": f.analyzed,
                    "impact_summary": f.impact_summary,
                    "exploitability_summary": f.exploitability_summary,
                    "verification_count": f.verification_count,
                    "independent_validations": f.independent_validations,
                    "evidence_chain": f.evidence_chain,
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

        Evidence Analysis:
        {context.evidence_analysis}

        Safe Attack Simulation Playbooks:
        {context.attack_simulation}

        Payload Injection Test Results (real-world, non-destructive):
        {context.payload_tests}

        Competitive Planning Data:
        parity_matrix={context.memory.get("competitive_parity_matrix", {})}
        maturity={context.memory.get("competitive_maturity", {})}
        initiatives={context.memory.get("competitive_initiatives", [])}
        references={context.memory.get("competitive_research_references", [])}

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
        5) Detailed Findings with OWASP, CVSS, MITRE, and CWE mapping
        6) Real-World Exploitability and Business-Impact Evaluation (non-destructive only)
        7) Orchestrator Learning Summary (reward, strategy shifts, convergence)
        8) Pentest-Style Real-World Payload Analysis (hypothesis, observed behavior, risk, false-positive checks)
        9) Evidence Confidence Calibration (hypothesis quality, signal strength, false-positive risk)
        10) Enterprise Compliance Mapping (PCI-DSS, NIST 800-53, ISO 27001, GDPR)
        11) Prioritized Remediation Roadmap
        12) Destructive-Mode Plan (if enabled): authorization prerequisites, rollback, blast-radius controls
        13) Competitive Research Roadmap (tool parity, maturity score, 30-60-90 day initiatives, KPIs)
        14) Conclusion

        Keep it explainable, concise, and professional markdown.
        """

        report_md = self.llm.generate(
            report_prompt,
            system_prompt=real_world_prompt("professional cybersecurity consultant"),
        )

        report_path = "reports/pentest_report.md"
        os.makedirs("reports", exist_ok=True)
        with open(report_path, "w") as f:
            f.write(report_md)

        self.log(f"Report generated successfully at {report_path}")
        return context
