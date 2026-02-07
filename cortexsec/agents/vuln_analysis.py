from cortexsec.core.agent import BaseAgent, PentestContext, Finding
from cortexsec.utils.http_security import run_http_security_quick_checks


class VulnAnalysisAgent(BaseAgent):
    """Agent responsible for analyzing data for vulnerabilities."""

    def __init__(self, llm, refinement_rounds: int = 2):
        super().__init__("VulnAnalysisAgent", llm)
        self.refinement_rounds = max(0, refinement_rounds)

    def _finding_key(self, finding: Finding) -> str:
        return f"{finding.title}|{finding.evidence}"

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

        improvement_log = context.memory.setdefault("vuln_analysis_improvements", [])

        for round_id in range(1, self.refinement_rounds + 1):
            current_findings = [finding.dict() for finding in dedupe.values()]
            refinement_prompt = f"""
            You are performing research-style iterative vulnerability refinement.
            Current candidate findings:
            findings={current_findings}

            Context:
            recon={context.recon_data}
            attack_surface={context.attack_surface}

            Tasks:
            1) Improve weak/unclear findings with stronger evidence and mitigations.
            2) Add only truly new vulnerabilities that are likely to be missed.
            3) Remove findings that are contradicted by the data.

            Return strict JSON: {{"findings": [ ... ], "research_notes": ["..."]}}
            """
            refined = self.llm.generate_json(
                refinement_prompt,
                system_prompt="You are a principal application security researcher. Be precise and evidence-driven.",
            )

            if not isinstance(refined, dict) or "error" in refined:
                improvement_log.append(
                    {
                        "round": round_id,
                        "status": "parse_error",
                        "details": refined.get("error") if isinstance(refined, dict) else "invalid response",
                    }
                )
                continue

            refined_findings = refined.get("findings", [])
            before_count = len(dedupe)

            for f_data in refined_findings:
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

            improvement_log.append(
                {
                    "round": round_id,
                    "status": "ok",
                    "delta_findings": len(dedupe) - before_count,
                    "research_notes": refined.get("research_notes", []),
                }
            )

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

        context.findings = list(dedupe.values())
        self.log(f"Analysis complete. Total unique findings: {len(context.findings)}")
        return context
