from typing import Dict, List

from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class ScientistAgent(BaseAgent):
    """Applies cyber-security scientific reasoning to findings and payload evidence."""

    def __init__(self, llm):
        super().__init__("ScientistAgent", llm)

    def _severity_weight(self, severity: str) -> float:
        table = {"Critical": 1.0, "High": 0.8, "Medium": 0.6, "Low": 0.3}
        return table.get(severity, 0.4)

    def _hypothesis_matrix(self, payload_tests: List[Dict]) -> Dict:
        total = len(payload_tests)
        strong = len([p for p in payload_tests if p.get("status") == "needs-review"])
        inconclusive = len([p for p in payload_tests if p.get("status") == "inconclusive"])
        ratio = round((strong / total), 3) if total else 0.0
        return {
            "tests_total": total,
            "signals_strong": strong,
            "signals_inconclusive": inconclusive,
            "signal_ratio": ratio,
            "hypothesis": "If controls are weak, non-destructive payloads should trigger reproducible response deltas.",
            "interpretation": "High signal ratio increases confidence of real weakness; low ratio favors false-positive classification.",
        }

    def _calibrate_finding(self, finding: Finding, signal_ratio: float) -> Finding:
        weight = self._severity_weight(finding.severity)
        prior = max(0.0, min(1.0, finding.confidence))
        posterior = round(min(1.0, (0.65 * prior) + (0.35 * (signal_ratio * weight + 0.2))), 3)
        finding.confidence = posterior
        return finding

    def run(self, context: PentestContext) -> PentestContext:
        self.log("Running cyber-security scientific analysis over hypotheses and evidence...")

        matrix = self._hypothesis_matrix(context.payload_tests)
        ratio = float(matrix.get("signal_ratio", 0.0))
        context.findings = [self._calibrate_finding(f, ratio) for f in context.findings]

        confidence_after = round(sum(f.confidence for f in context.findings) / len(context.findings), 3) if context.findings else 0.0
        false_positive_risk = "high" if ratio < 0.1 else "medium" if ratio < 0.3 else "low"

        context.scientific_analysis = {
            "hypothesis_matrix": matrix,
            "confidence_after_calibration": confidence_after,
            "false_positive_risk": false_positive_risk,
            "method": "Evidence-weighted confidence calibration",
        }
        context.history.append(
            {
                "agent": self.name,
                "message": "Scientific evidence calibration complete",
                "signal_ratio": ratio,
                "false_positive_risk": false_positive_risk,
            }
        )
        self.log(f"Scientific analysis complete. signal_ratio={ratio}, fp_risk={false_positive_risk}")
        return context
