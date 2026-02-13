from __future__ import annotations

from typing import Dict, List

from cortexsec.core.agent import Finding


def _normalized_text(finding: Finding) -> str:
    return f"{finding.title} {finding.description} {finding.evidence}".lower()


def map_to_owasp_top10(finding: Finding) -> str:
    text = _normalized_text(finding)

    if any(keyword in text for keyword in ["sqli", "sql injection", "xxe", "injection", "nosql"]):
        return "A03:2021 - Injection"
    if any(keyword in text for keyword in ["access control", "idor", "unauthorized", "privilege"]):
        return "A01:2021 - Broken Access Control"
    if any(keyword in text for keyword in ["header", "misconfiguration", "directory listing", "exposed admin"]):
        return "A05:2021 - Security Misconfiguration"
    if any(keyword in text for keyword in ["xss", "csrf", "integrity", "untrusted data"]):
        return "A08:2021 - Software and Data Integrity Failures"
    if any(keyword in text for keyword in ["auth", "session", "jwt", "token"]):
        return "A07:2021 - Identification and Authentication Failures"

    return "A09:2021 - Security Logging and Monitoring Failures"


def map_to_mitre_attack(finding: Finding) -> str:
    text = _normalized_text(finding)

    if any(keyword in text for keyword in ["sql injection", "xss", "command injection", "exploit public-facing"]):
        return "T1190"
    if any(keyword in text for keyword in ["bruteforce", "credential stuffing", "password spray"]):
        return "T1110"
    if any(keyword in text for keyword in ["discovery", "scan", "enumeration", "directory"]):
        return "T1595"

    return "T1595"


def map_to_cwe(finding: Finding) -> str:
    text = _normalized_text(finding)

    if "sql injection" in text or "sqli" in text:
        return "CWE-89"
    if "xss" in text or "cross-site scripting" in text:
        return "CWE-79"
    if "csrf" in text:
        return "CWE-352"
    if "access control" in text or "idor" in text:
        return "CWE-284"
    if "header" in text or "misconfiguration" in text:
        return "CWE-16"

    return "CWE-693"


def cvss_v31_base_score(finding: Finding) -> float:
    severity_to_score = {
        "critical": 9.1,
        "high": 7.8,
        "medium": 5.5,
        "low": 3.1,
    }
    return severity_to_score.get((finding.severity or "medium").lower(), 5.5)


def map_enterprise_controls(finding: Finding) -> Dict[str, List[str]]:
    text = _normalized_text(finding)

    controls = {
        "PCI-DSS": ["6.3.2", "6.5.1", "11.3.1"],
        "NIST 800-53": ["SI-2", "RA-5", "SA-11"],
        "ISO 27001": ["A.8.8", "A.8.28", "A.8.29"],
        "GDPR": ["Art. 25", "Art. 32"],
    }

    if any(keyword in text for keyword in ["auth", "credential", "access"]):
        controls["PCI-DSS"].append("8.3.1")
        controls["NIST 800-53"].append("IA-2")
        controls["ISO 27001"].append("A.5.17")

    return controls


def enrich_finding_with_compliance(finding: Finding) -> Finding:
    if not finding.owasp_mapping:
        finding.owasp_mapping = map_to_owasp_top10(finding)

    if not finding.mitre_mapping:
        finding.mitre_mapping = map_to_mitre_attack(finding)

    if not finding.cwe_id:
        finding.cwe_id = map_to_cwe(finding)

    if finding.cvss_score is None:
        finding.cvss_score = cvss_v31_base_score(finding)

    finding.compliance_tags = map_enterprise_controls(finding)
    return finding
