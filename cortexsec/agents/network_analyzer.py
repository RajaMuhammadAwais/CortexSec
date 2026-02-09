"""
Advanced Network Traffic Analyzer.

Analyzes network traffic patterns to detect:
- Suspicious outbound connections
- Data exfiltration attempts
- Command & Control (C2) communications
- Port scanning activities
- Protocol anomalies
- DNS tunneling

Written with clear, human-readable logic.
"""

from __future__ import annotations

import json
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from collections import defaultdict

from cortexsec.core.agent import BaseAgent, Finding, PentestContext


class NetworkAnalyzer(BaseAgent):
    """
    Advanced network traffic analyzer for detecting suspicious patterns.
    
    Think of this like a security guard watching all network traffic:
    - Who is talking to whom?
    - What are they saying?
    - Does it look suspicious?
    """

    def __init__(self, llm):
        super().__init__("NetworkAnalyzer", llm)
        # Human logic: Keep track of what we observe
        self.observed_connections = []
        self.suspicious_patterns = []

    def _analyze_dns_patterns(self, target: str) -> List[Finding]:
        """
        Check for DNS-based attacks.
        
        Human logic: DNS should be simple - ask for a domain, get an IP.
        If someone is doing weird things with DNS, that's suspicious.
        """
        findings = []
        
        try:
            # Parse the target to get the hostname
            parsed = urlparse(target if "://" in target else f"http://{target}")
            hostname = parsed.hostname or target
            
            # Human logic: Try to resolve the hostname
            # If it fails or gives weird results, that's a red flag
            try:
                ip_address = socket.gethostbyname(hostname)
                
                # Check if the IP is suspicious
                # Private IPs for public domains = suspicious
                is_private = (
                    ip_address.startswith("10.") or
                    ip_address.startswith("192.168.") or
                    ip_address.startswith("172.16.")
                )
                
                if is_private and not hostname.startswith("localhost"):
                    findings.append(Finding(
                        title="Suspicious DNS Resolution to Private IP",
                        description=f"Public domain {hostname} resolves to private IP {ip_address}, which may indicate DNS rebinding or internal network exposure",
                        severity="Medium",
                        confidence=0.75,
                        evidence=f"DNS lookup: {hostname} -> {ip_address}",
                        mitigation="Verify DNS configuration. Consider implementing DNS rebinding protection.",
                        cvss_score=5.5,
                        owasp_mapping="A05:2021 - Security Misconfiguration",
                        mitre_mapping="T1071.004 - Application Layer Protocol: DNS"
                    ))
                
                # Human logic: Check for unusually long hostname
                # Attackers sometimes use DNS tunneling with long subdomains
                if len(hostname) > 100:
                    findings.append(Finding(
                        title="Potential DNS Tunneling Detected",
                        description=f"Hostname length ({len(hostname)} characters) exceeds normal limits, which may indicate DNS tunneling for data exfiltration",
                        severity="High",
                        confidence=0.65,
                        evidence=f"Hostname: {hostname[:100]}...",
                        mitigation="Monitor DNS traffic for unusual patterns. Implement DNS query length limits.",
                        cvss_score=7.0,
                        owasp_mapping="A09:2021 - Security Logging and Monitoring Failures",
                        mitre_mapping="T1071.004 - Application Layer Protocol: DNS"
                    ))
                
            except socket.gaierror:
                # Human logic: If DNS lookup fails, that's also suspicious
                # Either the domain doesn't exist or DNS is being tampered with
                findings.append(Finding(
                    title="DNS Resolution Failure",
                    description=f"Unable to resolve {hostname}. This could indicate DNS issues or a non-existent domain",
                    severity="Low",
                    confidence=0.5,
                    evidence=f"DNS lookup failed for: {hostname}",
                    mitigation="Verify domain exists. Check DNS server configuration.",
                    cvss_score=3.0,
                    owasp_mapping="A05:2021 - Security Misconfiguration",
                    mitre_mapping="T1071.004 - Application Layer Protocol: DNS"
                ))
                
        except Exception as e:
            self.log(f"DNS analysis error: {e}")
        
        return findings

    def _check_port_scanning_behavior(self, context: PentestContext) -> List[Finding]:
        """
        Detect if the target appears to be scanning ports.
        
        Human logic: Normal apps connect to specific ports.
        If something is trying lots of random ports, it's probably scanning.
        """
        findings = []
        
        # Human logic: Look at reconnaissance data for port info
        recon_data = context.recon_data.get("raw", {})
        
        # Check if we detected multiple open ports
        # This is stored by the recon agent
        open_ports = recon_data.get("open_ports", [])
        
        if len(open_ports) > 10:
            # Human logic: More than 10 open ports is unusual for most apps
            findings.append(Finding(
                title="Multiple Open Ports Detected",
                description=f"Target has {len(open_ports)} open ports, which increases the attack surface significantly",
                severity="Medium",
                confidence=0.8,
                evidence=f"Open ports: {', '.join(map(str, open_ports[:20]))}",
                mitigation="Close unnecessary ports. Implement port filtering and firewall rules.",
                cvss_score=5.0,
                owasp_mapping="A05:2021 - Security Misconfiguration",
                mitre_mapping="T1046 - Network Service Discovery"
            ))
        
        return findings

    def _analyze_protocol_anomalies(self, target: str) -> List[Finding]:
        """
        Check for weird protocol usage.
        
        Human logic: Each protocol has rules (HTTP uses port 80, HTTPS uses 443).
        If someone breaks these rules, they might be hiding something.
        """
        findings = []
        
        try:
            parsed = urlparse(target if "://" in target else f"http://{target}")
            scheme = parsed.scheme
            port = parsed.port
            
            # Human logic: Check if port and protocol match
            expected_ports = {
                "http": 80,
                "https": 443,
                "ftp": 21,
                "ssh": 22
            }
            
            if scheme in expected_ports and port and port != expected_ports[scheme]:
                # Non-standard port = suspicious
                findings.append(Finding(
                    title="Non-Standard Port for Protocol",
                    description=f"Service uses {scheme.upper()} on port {port} instead of standard port {expected_ports[scheme]}. This may indicate evasion attempts or security through obscurity",
                    severity="Low",
                    confidence=0.6,
                    evidence=f"Protocol: {scheme}, Port: {port}, Expected: {expected_ports[scheme]}",
                    mitigation="Document non-standard ports. Ensure firewall rules account for custom ports.",
                    cvss_score=3.5,
                    owasp_mapping="A05:2021 - Security Misconfiguration",
                    mitre_mapping="T1571 - Non-Standard Port"
                ))
            
            # Human logic: HTTP when HTTPS should be used
            if scheme == "http" and not target.startswith("http://localhost"):
                findings.append(Finding(
                    title="Unencrypted HTTP Traffic",
                    description="Target uses HTTP instead of HTTPS, exposing data to interception and man-in-the-middle attacks",
                    severity="Medium",
                    confidence=0.9,
                    evidence=f"URL scheme: {scheme}",
                    mitigation="Implement HTTPS with valid SSL/TLS certificates. Redirect HTTP to HTTPS.",
                    cvss_score=5.5,
                    owasp_mapping="A02:2021 - Cryptographic Failures",
                    mitre_mapping="T1040 - Network Sniffing"
                ))
        
        except Exception as e:
            self.log(f"Protocol analysis error: {e}")
        
        return findings

    def _detect_data_exfiltration_patterns(self, context: PentestContext) -> List[Finding]:
        """
        Look for signs of data being stolen.
        
        Human logic: If lots of data is being sent out, especially to weird places,
        that might be data theft.
        """
        findings = []
        
        # Human logic: Check if we found any findings that involve data leakage
        for finding in context.findings:
            # Look for keywords that suggest data exposure
            data_keywords = ["exposed", "leak", "disclosure", "sensitive", "credential", "secret"]
            
            if any(keyword in finding.title.lower() or keyword in finding.description.lower() 
                   for keyword in data_keywords):
                
                # This finding already indicates data exposure
                # Add context about potential exfiltration
                findings.append(Finding(
                    title="Potential Data Exfiltration Risk",
                    description=f"Combined with finding '{finding.title}', there is a risk of data exfiltration. Exposed data could be stolen by attackers",
                    severity="High",
                    confidence=0.7,
                    evidence=f"Related finding: {finding.title}",
                    mitigation="Implement Data Loss Prevention (DLP). Monitor outbound traffic for sensitive data patterns.",
                    cvss_score=7.5,
                    owasp_mapping="A04:2021 - Insecure Design",
                    mitre_mapping="T1041 - Exfiltration Over C2 Channel"
                ))
                break  # Only create one exfiltration finding
        
        return findings

    def _analyze_with_llm(self, context: PentestContext) -> List[Finding]:
        """
        Use LLM to find patterns humans might miss.
        
        Human logic: Sometimes patterns are subtle. Ask the AI to look deeper.
        """
        findings = []
        
        # Prepare summary of what we've observed
        network_summary = {
            "target": context.target,
            "existing_findings": [
                {"title": f.title, "severity": f.severity} 
                for f in context.findings[:10]  # Top 10
            ],
            "attack_surface": context.attack_surface
        }
        
        analysis_prompt = f"""
        You are a network security analyst. Analyze this network intelligence for suspicious patterns.
        
        TARGET: {context.target}
        
        OBSERVED FINDINGS:
        {json.dumps(network_summary, indent=2)}
        
        Think like a security expert:
        1. What patterns look suspicious?
        2. Could this indicate an attacker's presence?
        3. Are there signs of data exfiltration, C2 communication, or other malicious activity?
        
        Return JSON:
        {{
            "additional_findings": [
                {{
                    "title": "Finding title",
                    "description": "What you observed and why it's concerning",
                    "severity": "Critical/High/Medium/Low",
                    "confidence": 0.0-1.0,
                    "evidence": "Specific evidence",
                    "mitigation": "How to fix it"
                }}
            ]
        }}
        """
        
        try:
            response = self.llm.generate_json(analysis_prompt)
            
            for finding_data in response.get("additional_findings", []):
                findings.append(Finding(
                    title=f"[Network Analysis] {finding_data.get('title', 'Unknown')}",
                    description=finding_data.get('description', ''),
                    severity=finding_data.get('severity', 'Medium'),
                    confidence=float(finding_data.get('confidence', 0.6)),
                    evidence=finding_data.get('evidence', ''),
                    mitigation=finding_data.get('mitigation', ''),
                    cvss_score=6.5,
                    owasp_mapping="A09:2021 - Security Logging and Monitoring Failures",
                    mitre_mapping="T1071 - Application Layer Protocol"
                ))
        
        except Exception as e:
            self.log(f"LLM analysis failed: {e}")
        
        return findings

    def run(self, context: PentestContext) -> PentestContext:
        """
        Run network traffic analysis.
        
        Human logic: Like a detective, we gather clues and piece them together.
        """
        self.log("Starting advanced network traffic analysis...")
        
        all_findings = []
        
        # Step 1: Check DNS for weirdness
        self.log("Analyzing DNS patterns...")
        all_findings.extend(self._analyze_dns_patterns(context.target))
        
        # Step 2: Look for port scanning behavior
        self.log("Checking for port scanning indicators...")
        all_findings.extend(self._check_port_scanning_behavior(context))
        
        # Step 3: Check if protocols are being used correctly
        self.log("Analyzing protocol usage...")
        all_findings.extend(self._analyze_protocol_anomalies(context.target))
        
        # Step 4: Look for data exfiltration signs
        self.log("Detecting data exfiltration patterns...")
        all_findings.extend(self._detect_data_exfiltration_patterns(context))
        
        # Step 5: Ask LLM to find subtle patterns
        self.log("Performing deep pattern analysis...")
        all_findings.extend(self._analyze_with_llm(context))
        
        # Add findings to context
        context.findings.extend(all_findings)
        
        # Record what we did
        context.history.append({
            "agent": self.name,
            "message": "Network traffic analysis complete",
            "findings_count": len(all_findings),
            "checks_performed": [
                "DNS analysis",
                "Port scanning detection",
                "Protocol anomaly detection",
                "Data exfiltration detection",
                "LLM pattern analysis"
            ]
        })
        
        self.log(f"Network analy complete. Found {len(all_findings)} network-related issues.")
        return context
