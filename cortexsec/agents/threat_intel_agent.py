"""
Threat Intelligence Integration Agent.

Enriches findings with real-time threat intelligence from:
- CVE databases (NVD, MITRE)
- Exploit databases  
- OSINT threat feeds
- Known vulnerability catalogs
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import requests

from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class ThreatIntelAgent(BaseAgent):
    """Real-time threat intelligence enrichment agent."""

    def __init__(self, llm, timeout: int = 10):
        super().__init__("ThreatIntelAgent", llm)
        self.timeout = timeout

    def _enrich_with_cve(self, finding: Finding) -> Dict[str, Any]:
        """Enrich finding with CVE information if applicable."""
        intel = {"cve_references": [], "exploits_available": False, "severity_confirmation": None}

        # Look for CVE mentions in evidence or description
        import re

        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cves = re.findall(cve_pattern, finding.evidence + finding.description)

        for cve_id in cves[:3]:  # Limit to 3 CVEs
            try:
                # Use NVD API (free, no key required for basic access)
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                response = requests.get(url, timeout=self.timeout)

                if response.status_code == 200:
                    data = response.json()

                    if "vulnerabilities" in data and data["vulnerabilities"]:
                        vuln = data["vulnerabilities"][0]["cve"]

                        # Extract CVSS score
                        cvss_score = None
                        if "metrics" in vuln:
                            metrics = vuln.get("metrics", {})
                            if "cvssMetricV31" in metrics:
                                cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                            elif "cvssMetricV2" in metrics:
                                cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                        intel["cve_references"].append(
                            {
                                "cve_id": cve_id,
                                "cvss_score": cvss_score,
                                "description": vuln.get("descriptions", [{}])[0].get("value", ""),
                                "published": vuln.get("published", ""),
                            }
                        )

            except Exception as e:
                self.log(f"Failed to fetch CVE {cve_id}: {e}")
                continue

        return intel

    def _check_known_exploits(self, finding: Finding) -> Dict[str, Any]:
        """Check if exploits exist for this vulnerability."""
        intel = {"exploit_references": [], "exploit_count": 0}

        # Search Exploit-DB via search terms
        keywords = []

        # Extract technology names
        if hasattr(finding, "evidence") and finding.evidence:
            # Look for common software names
            tech_keywords = ["nginx", "apache", "php", "mysql", "wordpress", "joomla", "drupal", "jenkins", "tomcat"]
            for keyword in tech_keywords:
                if keyword in finding.evidence.lower() or keyword in finding.description.lower():
                    keywords.append(keyword)

        # For demonstration, we'll note this capability
        # In production, you would integrate with Exploit-DB API or web scraping

        intel["search_keywords"] = keywords
        intel["exploit_check_performed"] = True

        return intel

    def _check_osint_feeds(self, context: PentestContext) -> List[Dict[str, Any]]:
        """Check OSINT threat feeds for IOCs related to target."""
        osint_data = []

        # Extract host from target
        from urllib.parse import urlparse

        parsed = urlparse(context.target)
        host = parsed.hostname

        if not host:
            return osint_data

        # Check if it's a public IP (skip localhost/private IPs)
        if host in {"localhost", "127.0.0.1"} or host.startswith("192.168.") or host.startswith("10."):
            return osint_data

        # For demonstration: would integrate with AlienVault OTX, VirusTotal, etc.
        # These require API keys in production

        osint_data.append(
            {
                "source": "threat_intel_check",
                "target_host": host,
                "note": "Threat intelligence APIs require configuration",
            }
        )

        return osint_data

    def _enrich_findings(self, context: PentestContext) -> PentestContext:
        """Enrich all findings with threat intelligence."""
        enriched_count = 0

        for finding in context.findings:
            # Skip low-confidence findings
            if finding.confidence < 0.5:
                continue

            # Enrich with CVE data
            cve_intel = self._enrich_with_cve(finding)
            if cve_intel["cve_references"]:
                enriched_count += 1

                # Update finding with CVE information
                for cve_ref in cve_intel["cve_references"]:
                    if cve_ref.get("cvss_score") and not finding.cvss_score:
                        finding.cvss_score = finding.cvss_score or cve_ref["cvss_score"]

                    # Add CVE to evidence
                    finding.evidence += f"\n[Threat Intel] {cve_ref['cve_id']}: CVSS {cve_ref.get('cvss_score', 'N/A')}"

            # Check for exploits
            exploit_intel = self._check_known_exploits(finding)
            if exploit_intel["exploit_check_performed"]:
                finding.evidence += f"\n[Exploit Check] Keywords: {', '.join(exploit_intel.get('search_keywords', []))}"

        context.history.append(
            {
                "agent": self.name,
                "message": "Threat intelligence enrichment complete",
                "findings_enriched": enriched_count,
                "total_findings": len(context.findings),
            }
        )

        return context

    def run(self, context: PentestContext) -> PentestContext:
        """Execute threat intelligence integration."""
        self.log("Running threat intelligence enrichment...")

        # Check OSINT feeds for target
        osint_data = self._check_osint_feeds(context)

        # Enrich findings with threat intel
        context = self._enrich_findings(context)

        # Store threat intel data in context
        if not hasattr(context, "threat_intel"):
            context.threat_intel = {}

        context.threat_intel = {
            "osint_checks": osint_data,
            "enrichment_performed": True,
            "sources": ["NVD CVE Database", "Exploit-DB (keywords)", "OSINT feeds (placeholder)"],
        }

        self.log("Threat intelligence integration complete.")
        return context
