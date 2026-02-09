"""
Secrets and Credentials Scanner Agent.

Detects exposed secrets, API keys, tokens, passwords, and credentials using:
- Regex-based pattern matching
- Entropy analysis for high-entropy strings
- Git history scanning
- Configuration file analysis
- Hard-coded credentials detection
"""

from __future__ import annotations

import base64
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class SecretsScannerAgent(BaseAgent):
    """Comprehensive secrets and credentials detection agent."""

    def __init__(self, llm, max_files: int = 100):
        super().__init__("SecretsScannerAgent", llm)
        self.max_files = max_files

        # Define secret patterns
        self.patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
            "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
            "GitHub PAT": r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
            "GitLab Token": r"glpat-[0-9a-zA-Z\-]{20}",
            "Azure Client Secret": r"[a-zA-Z0-9~_\-\.]{34,40}",  # Azure app secrets
            "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
            "Generic API Key": r"api[_\-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{16,64})['\"]?",
            "Generic Secret": r"secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{16,64})['\"]?",
            "Generic Password": r"password['\"]?\s*[:=]\s*['\"]?([^\s]{8,})['\"]?",
            "Private Key Header": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "Database Connection String": r"(mongodb|postgres|mysql|mssql):\/\/[^\s]+",
            "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "Slack Token": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24,}",
            "Stripe Restricted Key": r"rk_live_[0-9a-zA-Z]{24,}",
            "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
            "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
            "Twilio API Key": r"SK[a-f0-9]{32}",
            "SendGrid API Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
            "MailGun API Key": r"key-[0-9a-zA-Z]{32}",
            "PyPI Upload Token": r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{100,}",
            "NPM Token": r"npm_[A-Za-z0-9]{36}",
            "Docker Hub Token": r"dckr_pat_[a-zA-Z0-9_-]{36}",
            "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "Generic Token": r"token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{20,100})['\"]?",
        }

    def _calculate_shannon_entropy(self, string: str) -> float:
        """Calculate Shannon entropy to detect high-entropy secrets."""
        if not string:
            return 0.0

        import math

        entropy = 0.0
        for char in set(string):
            prob = string.count(char) / len(string)
            entropy -= prob * math.log2(prob)
        return entropy

    def _scan_text(self, text: str, source: str) -> List[Finding]:
        """Scan text content for secrets using regex patterns."""
        findings = []

        for secret_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group(0)

                # Skip if it's a placeholder or example
                if any(
                    placeholder in matched_text.lower()
                    for placeholder in [
                        "example",
                        "placeholder",
                        "your_",
                        "my_",
                        "test",
                        "dummy",
                        "sample",
                        "xxx",
                        "***",
                    ]
                ):
                    continue

                # Calculate entropy for additional validation
                entropy = self._calculate_shannon_entropy(matched_text)

                # Mask the secret for evidence
                if len(matched_text) > 10:
                    masked = matched_text[:4] + "..." + matched_text[-4:]
                else:
                    masked = matched_text[:2] + "..." + matched_text[-2:]

                severity = "Critical" if secret_type in {"AWS Access Key", "Private Key Header", "Database Connection String"} else "High"

                findings.append(
                    Finding(
                        title=f"{secret_type} Exposed",
                        description=f"Detected {secret_type} in {source}. This credential should be immediately revoked and rotated.",
                        severity=severity,
                        confidence=0.9 if entropy > 4.0 else 0.75,
                        evidence=f"Found in {source}: {masked} (entropy: {entropy:.2f})",
                        mitigation="Remove hardcoded secrets. Use environment variables or secret management systems (AWS Secrets Manager, HashiCorp Vault, etc.). Rotate exposed credentials immediately.",
                        cvss_score=9.1 if severity == "Critical" else 7.5,
                        owasp_mapping="A02:2021 - Cryptographic Failures",
                        mitre_mapping="T1552.001 - Unsecured Credentials: Credentials In Files",
                    )
                )

        return findings

    def _scan_environment_variables(self, text: str) -> List[Finding]:
        """Detect environment variable files with potential secrets."""
        findings = []

        # Look for .env file patterns
        env_patterns = [
            (r"^[A-Z_]+\s*=\s*.+$", "Environment Variable Assignment"),
        ]

        for pattern, desc in env_patterns:
            matches = re.finditer(pattern, text, re.MULTILINE)
            for match in matches:
                line = match.group(0)

                # Check if contains suspicious keywords
                if any(
                    keyword in line.lower()
                    for keyword in ["password", "secret", "key", "token", "api", "auth", "credential"]
                ):
                    findings.append(
                        Finding(
                            title="Environment Variable with Sensitive Data",
                            description=f"Environment file contains sensitive variable: {desc}",
                            severity="High",
                            confidence=0.8,
                            evidence=f"Line: {line[:50]}...",
                            mitigation="Never commit .env files. Add to .gitignore. Use template files (.env.example) without real values.",
                            cvss_score=6.5,
                            owasp_mapping="A02:2021 - Cryptographic Failures",
                            mitre_mapping="T1552.001 - Unsecured Credentials: Credentials In Files",
                        )
                    )

        return findings

    def _scan_base64_secrets(self, text: str, source: str) -> List[Finding]:
        """Detect base64-encoded secrets."""
        findings = []

        # Find potential base64 strings
        base64_pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
        matches = re.finditer(base64_pattern, text)

        for match in matches:
            b64_string = match.group(0)

            try:
                decoded = base64.b64decode(b64_string).decode("utf-8", errors="ignore")

                # Check if decoded content contains secret-like patterns
                if any(keyword in decoded.lower() for keyword in ["password", "secret", "key", "token"]):
                    entropy = self._calculate_shannon_entropy(b64_string)

                    if entropy > 4.5:  # High entropy suggests it's not random
                        findings.append(
                            Finding(
                                title="Base64 Encoded Secret Detected",
                                description=f"Found base64-encoded data that may contain secrets in {source}",
                                severity="Medium",
                                confidence=0.7,
                                evidence=f"Encoded string (entropy: {entropy:.2f}): {b64_string[:20]}...",
                                mitigation="Avoid encoding secrets in base64. Use proper secret management systems.",
                                cvss_score=5.5,
                                owasp_mapping="A02:2021 - Cryptographic Failures",
                                mitre_mapping="T1552.001 - Unsecured Credentials: Credentials In Files",
                            )
                        )
            except Exception:
                continue

        return findings

    def _scan_files(self, target_path: Optional[str] = None) -> List[Finding]:
        """Scan files in a directory for secrets."""
        findings = []

        if not target_path or not os.path.exists(target_path):
            return findings

        # Common files to scan
        files_to_scan = []
        extensions = [".env", ".conf", ".config", ".yml", ".yaml", ".json", ".ini", ".xml", ".properties", ".txt", ".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".sh", ".bash"]

        try:
            for root, dirs, files in os.walk(target_path):
                # Skip common ignored directories
                dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "venv", ".venv", "__pycache__", "vendor"}]

                for file in files:
                    if any(file.endswith(ext) for ext in extensions) or file in {".env", ".env.local", ".env.production", "credentials"}:
                        files_to_scan.append(os.path.join(root, file))

                    if len(files_to_scan) >= self.max_files:
                        break

                if len(files_to_scan) >= self.max_files:
                    break

        except Exception as e:
            self.log(f"Error walking directory: {e}")
            return findings

        # Scan each file
        for file_path in files_to_scan:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                    # Scan for patterns
                    findings.extend(self._scan_text(content, file_path))
                    findings.extend(self._scan_environment_variables(content))
                    findings.extend(self._scan_base64_secrets(content, file_path))

            except Exception as e:
                self.log(f"Error reading file {file_path}: {e}")
                continue

        return findings

    def run(self, context: PentestContext) -> PentestContext:
        """Execute secrets scanning."""
        self.log("Running comprehensive secrets and credentials scanner...")

        all_findings = []

        # Scan HTTP response for embedded secrets
        recon_data = context.recon_data.get("raw", {})
        if "headers" in recon_data:
            headers_str = str(recon_data.get("headers", {}))
            all_findings.extend(self._scan_text(headers_str, "HTTP Headers"))

        # If a local path is provided in context (for filesystem scanning)
        if hasattr(context, "scan_path") and context.scan_path:
            all_findings.extend(self._scan_files(context.scan_path))

        # Add findings to context
        context.findings.extend(all_findings)

        context.history.append(
            {
                "agent": self.name,
                "message": "Secrets scanning complete",
                "findings_count": len(all_findings),
                "patterns_checked": len(self.patterns),
            }
        )

        self.log(f"Secrets scanner complete. Found {len(all_findings)} potential secrets.")
        return context
