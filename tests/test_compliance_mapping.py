from cortexsec.agents.vuln_analysis import VulnAnalysisAgent
from cortexsec.core.agent import Finding, PentestContext
from cortexsec.utils.compliance_mapping import (
    cvss_v31_base_score,
    enrich_finding_with_compliance,
    map_to_cwe,
    map_to_mitre_attack,
    map_to_owasp_top10,
)


class DummyLLM:
    def __init__(self, json_response=None):
        self.json_response = json_response or {"findings": []}

    def generate_json(self, prompt: str, system_prompt: str = ""):
        return self.json_response


def test_compliance_mapping_for_sql_injection_finding():
    finding = Finding(
        title="SQL Injection in login endpoint",
        description="User-controlled query string is injectable",
        severity="High",
        confidence=0.8,
        evidence="sqlmap confirmed injectable parameter",
    )

    enriched = enrich_finding_with_compliance(finding)

    assert map_to_owasp_top10(enriched) == "A03:2021 - Injection"
    assert map_to_mitre_attack(enriched) == "T1190"
    assert map_to_cwe(enriched) == "CWE-89"
    assert enriched.cvss_score == cvss_v31_base_score(enriched)
    assert "PCI-DSS" in enriched.compliance_tags
    assert "NIST 800-53" in enriched.compliance_tags


def test_vuln_analysis_agent_enriches_missing_compliance_fields():
    context = PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {"error": "timeout"}},
    )

    llm = DummyLLM(
        json_response={
            "findings": [
                {
                    "title": "IDOR on /api/orders/{id}",
                    "description": "Unauthorized resource access possible",
                    "severity": "High",
                    "confidence": 0.7,
                    "evidence": "Order object accessible across tenants",
                    "mitigation": "Enforce object-level authorization checks",
                }
            ]
        }
    )

    out = VulnAnalysisAgent(llm).run(context)

    finding = out.findings[0]
    assert finding.owasp_mapping is not None
    assert finding.mitre_mapping is not None
    assert finding.cwe_id is not None
    assert finding.cvss_score is not None
    assert finding.compliance_tags
