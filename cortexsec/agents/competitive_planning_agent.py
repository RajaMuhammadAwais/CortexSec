from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from cortexsec.core.agent import BaseAgent, PentestContext


@dataclass(frozen=True)
class CapabilityGap:
    """Represents a market capability and whether CortexSec already covers it."""

    name: str
    competitor_reference: str
    status: str
    action: str


class CompetitivePlanningAgent(BaseAgent):
    """Builds a research-grounded roadmap to compete with pentesting ecosystems."""

    def __init__(self, llm):
        super().__init__("CompetitivePlanningAgent", llm)

    def _tool_parity_matrix(self, context: PentestContext) -> Dict[str, List[CapabilityGap]]:
        findings_count = len(context.findings)
        has_attack_graph = bool(context.attack_graph)
        has_payload_tests = bool(context.payload_tests)
        has_network_view = bool(context.memory.get("network_evidence")) or bool(context.recon_data.get("raw"))
        has_exploitability_conf = bool(context.exploitability_assessment)

        return {
            "OWASP ZAP": [
                CapabilityGap(
                    name="Passive + active web checks",
                    competitor_reference="ZAP baseline/full scan workflows",
                    status="covered" if findings_count > 0 else "partial",
                    action="Expand default passive checks and add authenticated spider profiles.",
                ),
                CapabilityGap(
                    name="Automation-first CI scanning",
                    competitor_reference="ZAP automation framework",
                    status="covered",
                    action="Ship reusable pipeline templates with severity gates and report artifacts.",
                ),
            ],
            "Burp Suite": [
                CapabilityGap(
                    name="Guided manual+AI workflow",
                    competitor_reference="Burp Scanner + Repeater style analyst loops",
                    status="covered" if has_payload_tests else "partial",
                    action="Add deterministic replay and side-by-side request/response diffing.",
                ),
                CapabilityGap(
                    name="Advanced issue triage",
                    competitor_reference="Burp confidence classification + advisory quality",
                    status="covered" if has_attack_graph and has_exploitability_conf else "partial",
                    action="Add false-positive risk, exploit preconditions, and business-owner routing fields.",
                ),
            ],
            "OWASP WSTG": [
                CapabilityGap(
                    name="Standards-aligned test coverage",
                    competitor_reference="OWASP WSTG test categories",
                    status="covered" if has_network_view else "partial",
                    action="Generate machine-readable WSTG coverage matrix (pass/fail/not-tested).",
                ),
                CapabilityGap(
                    name="Evidence traceability",
                    competitor_reference="WSTG reproducible methodology",
                    status="covered",
                    action="Attach command/output provenance to each high-confidence finding.",
                ),
            ],
        }

    def _calculate_maturity(self, matrix: Dict[str, List[CapabilityGap]]) -> Dict[str, float]:
        scores: Dict[str, float] = {}
        tool_totals: List[float] = []

        for tool, gaps in matrix.items():
            total = len(gaps)
            covered = sum(1 for gap in gaps if gap.status == "covered")
            partial = sum(1 for gap in gaps if gap.status == "partial")

            # covered=1.0, partial=0.5 keeps scoring simple and explainable
            score = ((covered + (0.5 * partial)) / total) if total else 0.0
            rounded_score = round(score, 3)
            scores[tool] = rounded_score
            tool_totals.append(rounded_score)

        scores["overall"] = round(sum(tool_totals) / len(tool_totals), 3) if tool_totals else 0.0
        return scores

    def _build_real_world_initiatives(self, matrix: Dict[str, List[CapabilityGap]], maturity: Dict[str, float]) -> List[Dict[str, str]]:
        partial_count = sum(1 for tool_gaps in matrix.values() for gap in tool_gaps if gap.status == "partial")

        initiatives: List[Dict[str, str]] = [
            {
                "name": "WSTG Evidence Coverage Export",
                "phase": "Phase 1 (0-30 days)",
                "priority": "P1",
                "scope": "Add CLI/report export for OWASP WSTG controls with evidence links and residual risk notes.",
                "real_world_problem": "Security teams fail audits when tests are not mapped to standards.",
                "success_metric": "100% high/critical findings carry WSTG mapping + evidence URI.",
            },
            {
                "name": "Analyst Replay Workbench",
                "phase": "Phase 1 (0-30 days)",
                "priority": "P1",
                "scope": "Implement deterministic replay for payload experiments with baseline/payload response diffs.",
                "real_world_problem": "False positives delay remediation and reduce trust in autonomous scans.",
                "success_metric": "Reduce disputed findings by 40% in internal validation runs.",
            },
            {
                "name": "CI/CD Security Adoption Pack",
                "phase": "Phase 2 (30-60 days)",
                "priority": "P1",
                "scope": "Provide GitHub/GitLab/Jenkins templates with policy gates and artifact publishing.",
                "real_world_problem": "Teams struggle to operationalize security testing in release pipelines.",
                "success_metric": "< 15 minutes setup time for first pipeline execution.",
            },
            {
                "name": "Exploitability Calibration Framework",
                "phase": "Phase 2 (30-60 days)",
                "priority": "P2",
                "scope": "Calibrate exploitability confidence using reproducibility and multi-signal evidence weighting.",
                "real_world_problem": "Uncalibrated confidence causes weak prioritization and patch fatigue.",
                "success_metric": "Top-10 findings precision above 85% in regression benchmark.",
            },
            {
                "name": "Enterprise Triage Routing",
                "phase": "Phase 3 (60-90 days)",
                "priority": "P2",
                "scope": "Add ownership routing (service/team), SLA tagging, and remediation tracking payloads.",
                "real_world_problem": "Findings remain unresolved when ownership and SLA context is missing.",
                "success_metric": "90% of findings auto-routed to a responsible service owner.",
            },
        ]

        if partial_count:
            initiatives.append(
                {
                    "name": "Parity Hardening Sprint",
                    "phase": "Continuous",
                    "priority": "P2",
                    "scope": f"Close {partial_count} partial-parity capabilities identified in the current matrix.",
                    "real_world_problem": "Capability gaps reduce confidence versus mature pentest platforms.",
                    "success_metric": f"Raise overall competitive maturity from {maturity['overall']} to >= 0.9.",
                }
            )

        return initiatives

    def _research_references(self) -> List[Dict[str, str]]:
        return [
            {
                "name": "OWASP Web Security Testing Guide",
                "url": "https://owasp.org/www-project-web-security-testing-guide/",
                "usage": "Test-case taxonomy and coverage modeling.",
            },
            {
                "name": "NIST SP 800-115",
                "url": "https://csrc.nist.gov/publications/detail/sp/800-115/final",
                "usage": "Evidence discipline and repeatable security test execution.",
            },
            {
                "name": "PTES",
                "url": "http://www.pentest-standard.org/index.php/Main_Page",
                "usage": "Operational penetration-testing workflow alignment.",
            },
            {
                "name": "FIRST CVSS v3.1",
                "url": "https://www.first.org/cvss/v3-1/specification-document",
                "usage": "Severity normalization and prioritization strategy.",
            },
        ]

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Building research-based competitive roadmap for real-world penetration-testing programs...")

        matrix = self._tool_parity_matrix(context)
        maturity = self._calculate_maturity(matrix)
        initiatives = self._build_real_world_initiatives(matrix, maturity)

        serialized_matrix = {
            tool: [
                {
                    "capability": gap.name,
                    "reference": gap.competitor_reference,
                    "status": gap.status,
                    "action": gap.action,
                }
                for gap in gaps
            ]
            for tool, gaps in matrix.items()
        }

        context.memory["competitive_parity_matrix"] = serialized_matrix
        context.memory["competitive_maturity"] = maturity
        context.memory["competitive_initiatives"] = initiatives
        context.memory["competitive_projects"] = initiatives  # backward-compatible alias
        context.memory["competitive_research_references"] = self._research_references()
        context.memory["competitive_summary"] = (
            "Research-based roadmap aligned with OWASP ZAP, Burp Suite, and OWASP WSTG prepared for real-world execution."
        )

        return context
