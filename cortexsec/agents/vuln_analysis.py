from cortexsec.core.agent import BaseAgent, PentestContext, Finding
from cortexsec.utils.http_security import run_http_security_quick_checks


class VulnAnalysisAgent(BaseAgent):
    """Agent responsible for analyzing data for vulnerabilities."""

    def __init__(self, llm, refinement_rounds: int = 2):
        super().__init__("VulnAnalysisAgent", llm)
        self.refinement_rounds = max(0, refinement_rounds)

    def _finding_key(self, finding: Finding) -> str:
        return f"{finding.title}|{finding.evidence}"


    def _severity_weight(self, severity: str) -> float:
        table = {"Critical": 1.0, "High": 0.8, "Medium": 0.6, "Low": 0.3}
        return table.get(severity, 0.4)

    def _build_hypothesis_matrix(self, payload_tests: list) -> dict:
        total = len(payload_tests)
        strong = len([p for p in payload_tests if p.get("status") == "needs-review"])
        inconclusive = len([p for p in payload_tests if p.get("status") == "inconclusive"])
        signal_ratio = round((strong / total), 3) if total else 0.0
        return {
            "tests_total": total,
            "signals_strong": strong,
            "signals_inconclusive": inconclusive,
            "signal_ratio": signal_ratio,
            "hypothesis": "Weak controls should produce reproducible behavior deltas under non-destructive payloads.",
        }

    def _calibrate_confidence(self, finding: Finding, signal_ratio: float) -> Finding:
        prior = max(0.0, min(1.0, finding.confidence))
        posterior = round(min(1.0, (0.7 * prior) + (0.3 * (signal_ratio * self._severity_weight(finding.severity) + 0.2))), 3)
        finding.confidence = posterior
        return finding

    def _payload_signal_to_finding(self, signal: dict) -> Finding:
        evidence = signal.get("evidence", {})
        payload_type = signal.get("payload_type", "unknown")
        goal = signal.get("goal", "payload-based validation")
        return Finding(
            title=f"Payload-Test Signal: {payload_type}",
            description=(
                "Safe payload injection produced a behavioral difference requiring manual triage. "
                f"Goal: {goal}."
            ),
            severity="Medium",
            confidence=0.7,
            evidence=str(evidence),
            mitigation=(
                "Harden input validation and canonicalization, enforce strict authorization checks on all state transitions, "
                "and apply consistent output encoding/sanitization."
            ),
            cvss_score=5.8,
            owasp_mapping="A01/A03/A04",
            mitre_mapping="T1190",
        )


    def run(self, context: PentestContext) -> PentestContext:
        self.log("Analyzing data for vulnerabilities...")

        analysis_prompt = f"""
        Based on the reconnaissance and attack-surface data:
        recon={context.recon_data}
        attack_surface={context.attack_surface}

        Identify potential vulnerabilities. For each vulnerability, provide:
        - title
        - description
        - severity (Low, Medium, High, Critical)
        - confidence (0.0 to 1.0)
        - evidence
        - mitigation
        - cvss_score (0.0 to 10.0)
        - owasp_mapping
        - mitre_mapping

        Return strict JSON: {{"findings": [ ... ]}}
        """

        results = self.llm.generate_json(analysis_prompt, system_prompt="You are a senior vulnerability researcher.")
        llm_findings = results.get("findings", []) if isinstance(results, dict) else []

        dedupe = {self._finding_key(f): f for f in context.findings}

        for f_data in llm_findings:
            finding = Finding(
                title=f_data.get("title", "Unknown"),
                description=f_data.get("description", ""),
                severity=f_data.get("severity", "Low"),
                confidence=float(f_data.get("confidence", 0.5)),
                evidence=f_data.get("evidence", ""),
                mitigation=f_data.get("mitigation", ""),
                cvss_score=f_data.get("cvss_score"),
                owasp_mapping=f_data.get("owasp_mapping"),
                mitre_mapping=f_data.get("mitre_mapping"),
            )
            dedupe[self._finding_key(finding)] = finding

        raw_recon = context.recon_data.get("raw", {})
        headers = raw_recon.get("headers")
        recon_error = raw_recon.get("error")

        if isinstance(headers, dict) and headers and not recon_error:
            quick_findings = run_http_security_quick_checks(context.target, headers)
            for f_data in quick_findings:
                finding = Finding(
                    title=f_data["title"],
                    description=f_data["description"],
                    severity=f_data["severity"],
                    confidence=f_data["confidence"],
                    evidence=f_data["evidence"],
                    mitigation=f_data.get("mitigation"),
                    cvss_score=f_data.get("cvss_score"),
                    owasp_mapping=f_data.get("owasp_mapping"),
                    mitre_mapping=f_data.get("mitre_mapping"),
                )
                dedupe[self._finding_key(finding)] = finding
        else:
            self.log("Skipping HTTP quick checks because recon did not return response headers.")

        payload_signals = [p for p in context.payload_tests if p.get("status") == "needs-review"]
        for signal in payload_signals:
            finding = self._payload_signal_to_finding(signal)
            dedupe[self._finding_key(finding)] = finding

        matrix = self._build_hypothesis_matrix(context.payload_tests)
        signal_ratio = float(matrix.get("signal_ratio", 0.0))
        context.findings = [self._calibrate_confidence(f, signal_ratio) for f in list(dedupe.values())]

        context.scientific_analysis = {
            "method": "Embedded scientific confidence calibration in VulnAnalysisAgent",
            "hypothesis_matrix": matrix,
            "false_positive_risk": "high" if signal_ratio < 0.1 else "medium" if signal_ratio < 0.3 else "low",
        }

        self.log(f"Analysis complete. Total unique findings: {len(context.findings)}")
        return context
