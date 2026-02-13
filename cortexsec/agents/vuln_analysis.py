from cortexsec.core.agent import BaseAgent, PentestContext, Finding
from cortexsec.utils.http_security import run_http_security_quick_checks
from cortexsec.agents.real_world_guidance import real_world_prompt
from cortexsec.utils.compliance_mapping import enrich_finding_with_compliance


class VulnAnalysisAgent(BaseAgent):
    """Agent responsible for analyzing data for vulnerabilities."""

    def __init__(self, llm, refinement_rounds: int = 2):
        super().__init__("VulnAnalysisAgent", llm)
        self.refinement_rounds = max(0, refinement_rounds)

    def _finding_key(self, finding: Finding) -> str:
        return f"{finding.title}|{finding.evidence}"


    def _append_evidence(self, finding: Finding, source: str, detail: str) -> Finding:
        finding.evidence_chain.append({"source": source, "detail": detail})
        if source not in finding.independent_validations:
            finding.independent_validations.append(source)
        finding.verification_count = len(finding.independent_validations)
        return finding

    def _apply_escalation_gate(self, finding: Finding) -> Finding:
        # Enforce 2-agent confirmation minimum for Critical/High issues
        # Verification count tracks independent validations (e.g., tool + LLM, or multiple tools)
        if finding.severity in {"Critical", "High"} and finding.verification_count < 2:
            self.log(f"Escalation gate: Downgrading {finding.title} ({finding.severity}) due to insufficient validation (count={finding.verification_count})")
            finding.severity = "Medium"
            finding.description = (
                f"{finding.description} [Escalation Gate: Downgraded from Critical/High pending multi-agent verification]"
            ).strip()
            finding.confidence = min(finding.confidence, 0.65)
            
        # Audit trail for decisions
        finding.evidence_chain.append({
            "source": "EscalationGate",
            "decision": "verified" if finding.verification_count >= 2 else "downgraded",
            "rationale": f"Verification count: {finding.verification_count}",
            "timestamp": "2026-02-13T00:00:00Z" # Placeholder for real timestamp
        })
        return finding

    def _severity_weight(self, severity: str) -> float:
        table = {"Critical": 1.0, "High": 0.8, "Medium": 0.6, "Low": 0.3}
        return table.get(severity, 0.4)

    def _build_hypothesis_matrix(self, payload_tests: list) -> dict:
        total = len(payload_tests)
        strong = len([p for p in payload_tests if p.get("status") == "needs-review"])
        weak = len([p for p in payload_tests if p.get("status") == "weak-signal"])
        inconclusive = len([p for p in payload_tests if p.get("status") == "inconclusive"])

        reproducible = 0
        perturbation_total = 0
        for p in payload_tests:
            evidence = p.get("evidence", {}) if isinstance(p, dict) else {}
            perturbation_total += int(evidence.get("perturbation_score", 0) or 0)
            if evidence.get("reproducible") is True:
                reproducible += 1

        weighted_signal = strong + (0.35 * weak)
        signal_ratio = round((weighted_signal / total), 3) if total else 0.0
        reproducibility_ratio = round((reproducible / max(strong, 1)), 3) if strong else 0.0
        mean_perturbation = round((perturbation_total / total), 3) if total else 0.0

        return {
            "tests_total": total,
            "signals_strong": strong,
            "signals_weak": weak,
            "signals_inconclusive": inconclusive,
            "signal_ratio": signal_ratio,
            "reproducibility_ratio": reproducibility_ratio,
            "mean_perturbation": mean_perturbation,
            "hypothesis": "Weak controls should produce reproducible payload perturbations that exceed paired neutral controls.",
        }

    def _calibrate_confidence(self, finding: Finding, signal_ratio: float, reproducibility_ratio: float, mean_perturbation: float) -> Finding:
        prior = max(0.0, min(1.0, finding.confidence))
        severity_term = signal_ratio * self._severity_weight(finding.severity)
        evidence_term = (0.55 * severity_term) + (0.3 * reproducibility_ratio) + (0.15 * min(mean_perturbation / 4.0, 1.0))
        posterior = round(min(1.0, (0.65 * prior) + (0.35 * (evidence_term + 0.2))), 3)
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

        Identify potential vulnerabilities. Also process any findings from external tools provided in the recon data.
        For each vulnerability, provide:
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

        results = self.llm.generate_json(
            analysis_prompt,
            system_prompt=real_world_prompt("senior vulnerability researcher"),
        )
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
            finding = self._append_evidence(finding, "llm-analysis", finding.evidence or "model output")
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
                finding = self._append_evidence(finding, "http-quick-check", finding.evidence)
                dedupe[self._finding_key(finding)] = finding
        else:
            self.log("Skipping HTTP quick checks because recon did not return response headers.")

        payload_signals = [p for p in context.payload_tests if p.get("status") == "needs-review"]
        for signal in payload_signals:
            finding = self._payload_signal_to_finding(signal)
            finding = self._append_evidence(finding, "payload-validation", finding.evidence)
            dedupe[self._finding_key(finding)] = finding

        matrix = self._build_hypothesis_matrix(context.payload_tests)
        signal_ratio = float(matrix.get("signal_ratio", 0.0))
        reproducibility_ratio = float(matrix.get("reproducibility_ratio", 0.0))
        mean_perturbation = float(matrix.get("mean_perturbation", 0.0))
        context.findings = [
            self._calibrate_confidence(f, signal_ratio, reproducibility_ratio, mean_perturbation)
            for f in list(dedupe.values())
        ]

        fp_risk = "high"
        if signal_ratio >= 0.35 and reproducibility_ratio >= 0.5:
            fp_risk = "low"
        elif signal_ratio >= 0.15:
            fp_risk = "medium"

        context.evidence_analysis = {
            "method": "Evidence-based confidence calibration in VulnAnalysisAgent",
            "hypothesis_matrix": matrix,
            "false_positive_risk": fp_risk,
        }

        # Process external tool reports directly
        external_reports = context.recon_data.get("external_tool_report", {})
        for tool_name, report in external_reports.items():
            tool_findings = report.get("findings", [])
            for tf in tool_findings:
                finding = Finding(
                    title=f"[{tool_name.upper()}] {tf.get('type', 'Security Finding')}",
                    description=tf.get("description", f"Finding detected by {tool_name}"),
                    severity=tf.get("severity", "Medium"),
                    confidence=0.9,  # High confidence for tool-confirmed findings
                    evidence=tf.get("evidence", ""),
                    mitigation=tf.get("mitigation", "Follow tool-specific remediation guidance."),
                    cvss_score=tf.get("cvss_score", 5.0),
                    owasp_mapping=tf.get("owasp_mapping", "A05:2021 - Security Misconfiguration"),
                    mitre_mapping=tf.get("mitre_mapping", "T1595 - Active Scanning"),
                )
                finding = self._append_evidence(finding, f"tool:{tool_name}", finding.evidence)
                dedupe[self._finding_key(finding)] = finding

        context.findings = [
            enrich_finding_with_compliance(self._apply_escalation_gate(finding))
            for finding in list(dedupe.values())
        ]

        self.log(f"Analysis complete. Total unique findings: {len(context.findings)}")
        return context
