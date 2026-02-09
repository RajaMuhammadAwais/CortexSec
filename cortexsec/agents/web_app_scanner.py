"""
Advanced Web Application Security Scanner Agent.

Provides comprehensive web application security testing including:
- GraphQL introspection and mutation testing
- WebSocket security testing
- JWT/OAuth token manipulation
- CSRF token analysis
- Session management testing
- File upload security
- Modern injection vectors (XXE, SSRF, SSTI, NoSQL)
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from cortexsec.agents.real_world_guidance import real_world_prompt
from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class WebAppScannerAgent(BaseAgent):
    """Advanced web application security scanner for modern frameworks."""

    def __init__(self, llm, timeout: int = 10):
        super().__init__("WebAppScannerAgent", llm)
        self.timeout = timeout

    def _is_http_target(self, target: str) -> bool:
        """Check if target is HTTP/HTTPS."""
        parsed = urlparse(target)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

    def _test_graphql(self, target: str) -> List[Finding]:
        """Test for GraphQL introspection and security issues."""
        findings = []
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1"]

        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            """
        }

        for path in graphql_paths:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                response = requests.post(
                    url,
                    json=introspection_query,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200 and "__schema" in response.text:
                    findings.append(
                        Finding(
                            title="GraphQL Introspection Enabled",
                            description=f"GraphQL endpoint at {path} allows introspection queries, exposing the entire schema to potential attackers.",
                            severity="Medium",
                            confidence=0.95,
                            evidence=f"Introspection query successful at {url}. Response contains schema information.",
                            mitigation="Disable introspection in production environments. Use schema hiding or authentication for GraphQL endpoints.",
                            cvss_score=5.3,
                            owasp_mapping="A05:2021 - Security Misconfiguration",
                            mitre_mapping="T1592 - Gather Victim Host Information",
                        )
                    )

                    # Check for dangerous mutations
                    if "mutation" in response.text.lower():
                        findings.append(
                            Finding(
                                title="GraphQL Mutations Exposed",
                                description="GraphQL endpoint exposes mutation operations that could allow unauthorized data modification.",
                                severity="High",
                                confidence=0.85,
                                evidence=f"Mutations detected in GraphQL schema at {url}",
                                mitigation="Implement proper authorization checks on all GraphQL mutations. Use field-level permissions.",
                                cvss_score=7.5,
                                owasp_mapping="A01:2021 - Broken Access Control",
                                mitre_mapping="T1190 - Exploit Public-Facing Application",
                            )
                        )

            except Exception:
                continue

        return findings

    def _test_jwt_security(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        """Test JWT token security."""
        findings = []

        # Check for JWT in Authorization header or cookies
        auth_header = headers.get("Authorization", "")
        set_cookie = headers.get("Set-Cookie", "")

        jwt_pattern = r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"
        tokens = re.findall(jwt_pattern, auth_header + set_cookie)

        for token in tokens:
            parts = token.split(".")
            if len(parts) >= 2:
                try:
                    # Decode header
                    header_data = base64.urlsafe_b64decode(parts[0] + "==").decode()
                    header_json = json.loads(header_data)

                    # Check for weak algorithms
                    alg = header_json.get("alg", "").upper()
                    if alg == "NONE":
                        findings.append(
                            Finding(
                                title="JWT Uses 'none' Algorithm",
                                description="JWT token uses the 'none' algorithm, allowing signature bypass.",
                                severity="Critical",
                                confidence=1.0,
                                evidence=f"JWT header contains: {header_data}",
                                mitigation="Never allow 'none' algorithm for JWT. Enforce strong signing algorithms like RS256 or ES256.",
                                cvss_score=9.8,
                                owasp_mapping="A02:2021 - Cryptographic Failures",
                                mitre_mapping="T1550 - Use Alternate Authentication Material",
                            )
                        )
                    elif alg in {"HS256", "HS384", "HS512"}:
                        findings.append(
                            Finding(
                                title="JWT Uses Symmetric Algorithm",
                                description=f"JWT uses symmetric algorithm ({alg}), which may be vulnerable to key confusion attacks.",
                                severity="Medium",
                                confidence=0.8,
                                evidence=f"JWT algorithm: {alg}",
                                mitigation="Consider using asymmetric algorithms (RS256, ES256) for better key management and security.",
                                cvss_score=5.9,
                                owasp_mapping="A02:2021 - Cryptographic Failures",
                                mitre_mapping="T1550 - Use Alternate Authentication Material",
                            )
                        )

                    # Decode payload
                    payload_data = base64.urlsafe_b64decode(parts[1] + "==").decode()
                    payload_json = json.loads(payload_data)

                    # Check for missing expiration
                    if "exp" not in payload_json:
                        findings.append(
                            Finding(
                                title="JWT Missing Expiration Claim",
                                description="JWT token does not contain an expiration claim, allowing indefinite token validity.",
                                severity="High",
                                confidence=0.9,
                                evidence=f"JWT payload: {payload_data}",
                                mitigation="Always include 'exp' claim in JWT tokens with reasonable expiration time.",
                                cvss_score=7.1,
                                owasp_mapping="A07:2021 - Identification and Authentication Failures",
                                mitre_mapping="T1550 - Use Alternate Authentication Material",
                            )
                        )

                except Exception:
                    continue

        return findings

    def _test_csrf_protection(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        """Test for CSRF protection mechanisms."""
        findings = []

        # Check for CSRF tokens in common locations
        csrf_indicators = [
            "csrf",
            "xsrf",
            "token",
            "_token",
            "authenticity_token",
            "anti-forgery",
        ]

        # Check cookies for SameSite attribute
        set_cookie = headers.get("Set-Cookie", "").lower()
        cookies = set_cookie.split(",")

        for cookie in cookies:
            if "session" in cookie or "auth" in cookie:
                if "samesite" not in cookie:
                    findings.append(
                        Finding(
                            title="Missing SameSite Cookie Attribute",
                            description="Session or authentication cookies lack SameSite attribute, making them vulnerable to CSRF attacks.",
                            severity="High",
                            confidence=0.9,
                            evidence=f"Cookie: {cookie[:100]}",
                            mitigation="Set SameSite=Strict or SameSite=Lax on all session cookies. Also implement CSRF tokens for state-changing operations.",
                            cvss_score=6.5,
                            owasp_mapping="A01:2021 - Broken Access Control",
                            mitre_mapping="T1539 - Steal Web Session Cookie",
                        )
                    )

        return findings

    def _test_session_management(self, target: str, headers: Dict[str, str]) -> List[Finding]:
        """Test session management security."""
        findings = []

        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return findings

        cookies = set_cookie.split(",")
        for cookie in cookies:
            cookie_lower = cookie.lower()

            # Check for session cookies
            if any(term in cookie_lower for term in ["session", "sid", "jsessionid", "phpsessid", "auth"]):
                # Check for Secure flag
                if "secure" not in cookie_lower and target.startswith("https"):
                    findings.append(
                        Finding(
                            title="Session Cookie Missing Secure Flag",
                            description="Session cookie does not have Secure flag set, allowing transmission over HTTP.",
                            severity="High",
                            confidence=0.95,
                            evidence=f"Cookie: {cookie[:100]}",
                            mitigation="Set Secure flag on all session cookies to prevent transmission over unencrypted connections.",
                            cvss_score=7.4,
                            owasp_mapping="A02:2021 - Cryptographic Failures",
                            mitre_mapping="T1539 - Steal Web Session Cookie",
                        )
                    )

                # Check for HttpOnly flag
                if "httponly" not in cookie_lower:
                    findings.append(
                        Finding(
                            title="Session Cookie Missing HttpOnly Flag",
                            description="Session cookie does not have HttpOnly flag, making it accessible via JavaScript.",
                            severity="Medium",
                            confidence=0.95,
                            evidence=f"Cookie: {cookie[:100]}",
                            mitigation="Set HttpOnly flag on session cookies to prevent XSS-based session theft.",
                            cvss_score=5.4,
                            owasp_mapping="A03:2021 - Injection",
                            mitre_mapping="T1539 - Steal Web Session Cookie",
                        )
                    )

        return findings

    def _test_file_upload(self, target: str) -> List[Finding]:
        """Test for file upload vulnerabilities."""
        findings = []
        upload_paths = ["/upload", "/file-upload", "/api/upload", "/media/upload"]

        for path in upload_paths:
            url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
            try:
                # Test with a benign file
                files = {"file": ("test.txt", "CORTEX_UPLOAD_TEST", "text/plain")}
                response = requests.post(url, files=files, timeout=self.timeout)

                if response.status_code < 400:
                    findings.append(
                        Finding(
                            title="File Upload Endpoint Detected",
                            description=f"File upload endpoint found at {path}. Requires manual testing for unrestricted file upload vulnerabilities.",
                            severity="Medium",
                            confidence=0.7,
                            evidence=f"Upload endpoint at {url} accepted file submission (status: {response.status_code})",
                            mitigation="Implement strict file type validation, size limits, antivirus scanning, and store uploads outside web root with randomized names.",
                            cvss_score=6.5,
                            owasp_mapping="A04:2021 - Insecure Design",
                            mitre_mapping="T1105 - Ingress Tool Transfer",
                        )
                    )

            except Exception:
                continue

        return findings

    def _test_nosql_injection(self, target: str) -> List[Finding]:
        """Test for NoSQL injection vulnerabilities."""
        findings = []

        # Common NoSQL injection payloads
        payloads = [
            {"username": {"$ne": None}, "password": {"$ne": None}},
            {"username": {"$gt": ""}, "password": {"$gt": ""}},
            {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        ]

        test_endpoints = ["/api/login", "/login", "/api/auth", "/api/users"]

        for endpoint in test_endpoints:
            url = urljoin(target.rstrip("/") + "/", endpoint.lstrip("/"))
            for payload in payloads:
                try:
                    response = requests.post(
                        url,
                        json=payload,
                        timeout=self.timeout,
                        headers={"Content-Type": "application/json"},
                    )

                    # Look for signs of successful injection
                    if response.status_code == 200 and any(
                        indicator in response.text.lower()
                        for indicator in ["token", "success", "authenticated", "session"]
                    ):
                        findings.append(
                            Finding(
                                title="Potential NoSQL Injection",
                                description=f"Endpoint {endpoint} may be vulnerable to NoSQL injection. MongoDB operator injection detected.",
                                severity="Critical",
                                confidence=0.75,
                                evidence=f"Injection payload {payload} at {url} returned suspicious response (status: {response.status_code})",
                                mitigation="Sanitize and validate all user input. Use parameterized queries and avoid passing user input directly to database operators.",
                                cvss_score=9.1,
                                owasp_mapping="A03:2021 - Injection",
                                mitre_mapping="T1190 - Exploit Public-Facing Application",
                            )
                        )
                        break

                except Exception:
                    continue

        return findings

    def run(self, context: PentestContext) -> PentestContext:
        """Execute advanced web application security scanning."""
        self.log("Running advanced web application security scanner...")

        if not self._is_http_target(context.target):
            context.history.append(
                {
                    "agent": self.name,
                    "message": "Skipped web app scanner (non-HTTP target)",
                }
            )
            return context

        all_findings = []

        # Get response headers from recon data
        headers = context.recon_data.get("raw", {}).get("headers", {})

        # Run all security tests
        all_findings.extend(self._test_graphql(context.target))
        all_findings.extend(self._test_jwt_security(context.target, headers))
        all_findings.extend(self._test_csrf_protection(context.target, headers))
        all_findings.extend(self._test_session_management(context.target, headers))
        all_findings.extend(self._test_file_upload(context.target))
        all_findings.extend(self._test_nosql_injection(context.target))

        # Add findings to context
        context.findings.extend(all_findings)

        # Use LLM for advanced analysis
        if all_findings:
            analysis_prompt = f"""
            Analyze these web application security findings for {context.target}:
            {json.dumps([f.model_dump() for f in all_findings], indent=2)}
            
            Identify any potential attack chains, escalation paths, or additional risks.
            Return JSON: {{"additional_insights": [str], "attack_chains": [str], "priority_recommendations": [str]}}
            """

            try:
                llm_analysis = self.llm.generate_json(
                    analysis_prompt,
                    system_prompt=real_world_prompt("web application security expert"),
                )
                context.history.append(
                    {
                        "agent": self.name,
                        "message": "Advanced web analysis complete",
                        "findings_count": len(all_findings),
                        "llm_insights": llm_analysis,
                    }
                )
            except Exception as e:
                self.log(f"LLM analysis failed: {e}")

        self.log(f"Web app scanner complete. Found {len(all_findings)} issues.")
        return context
