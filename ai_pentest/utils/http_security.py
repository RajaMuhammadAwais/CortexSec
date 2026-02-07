from typing import Dict, Any, List


def run_http_security_quick_checks(target: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Run lightweight HTTP security checks based on common real-world hardening guidance
    (OWASP secure headers recommendations).
    """
    findings: List[Dict[str, Any]] = []

    normalized_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    is_https = target.lower().startswith("https://")

    required_headers = [
        ("content-security-policy", "Missing Content-Security-Policy header", "High"),
        ("x-content-type-options", "Missing X-Content-Type-Options header", "Medium"),
        ("x-frame-options", "Missing X-Frame-Options header", "Medium"),
        ("referrer-policy", "Missing Referrer-Policy header", "Low"),
    ]

    if is_https:
        required_headers.append(("strict-transport-security", "Missing Strict-Transport-Security header", "High"))

    for header_name, title, severity in required_headers:
        if header_name not in normalized_headers:
            findings.append(
                {
                    "title": title,
                    "description": f"The target did not return the `{header_name}` response header.",
                    "severity": severity,
                    "confidence": 0.95,
                    "evidence": f"Observed headers: {sorted(list(normalized_headers.keys()))}",
                    "mitigation": f"Configure the web server or reverse proxy to include `{header_name}` with a secure value.",
                    "owasp_mapping": "A05:2021 - Security Misconfiguration",
                    "cvss_score": 6.5 if severity == "High" else 4.3 if severity == "Medium" else 3.1,
                    "mitre_mapping": "T1190 - Exploit Public-Facing Application",
                    "source": "quick-check",
                }
            )

    server_header = normalized_headers.get("server", "")
    if server_header and server_header.lower() not in {"unknown", "none"}:
        findings.append(
            {
                "title": "Server banner exposed",
                "description": "The `Server` header discloses software details that can help attackers fingerprint the stack.",
                "severity": "Low",
                "confidence": 0.9,
                "evidence": f"Server header value: {server_header}",
                "mitigation": "Suppress detailed server banners or return a generic value via server/proxy configuration.",
                "owasp_mapping": "A05:2021 - Security Misconfiguration",
                "cvss_score": 2.6,
                "mitre_mapping": "T1592 - Gather Victim Host Information",
                "source": "quick-check",
            }
        )

    return findings

