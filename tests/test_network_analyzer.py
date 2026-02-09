"""Tests for Network Analyzer."""

import pytest

from cortexsec.agents.network_analyzer import NetworkAnalyzer
from cortexsec.core.agent import PentestContext, Finding


class DummyLLM:
    def __init__(self, json_responses=None):
        self.json_responses = json_responses or []
        self.call_count = 0

    def generate_json(self, prompt: str, system_prompt: str = ""):
        if self.call_count < len(self.json_responses):
            response = self.json_responses[self.call_count]
            self.call_count += 1
            return response
        return {"additional_findings": []}


def base_context():
    return PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {}, "analysis": {}},
    )


def test_network_analyzer_initialization():
    """Test network analyzer initializes correctly."""
    agent = NetworkAnalyzer(DummyLLM())
    
    assert agent.name == "NetworkAnalyzer"
    assert agent.observed_connections == []
    assert agent.suspicious_patterns == []


def test_http_protocol_detection():
    """Test detection of unencrypted HTTP usage."""
    agent = NetworkAnalyzer(DummyLLM())
    context = PentestContext(
        target="http://example.com",
        mode="authorized"
    )
    
    findings = agent._analyze_protocol_anomalies(context.target)
    
    # Should detect HTTP instead of HTTPS
    assert len(findings) > 0
    assert any("HTTP" in f.title for f in findings)


def test_non_standard_port_detection():
    """Test detection of non-standard ports."""
    agent = NetworkAnalyzer(DummyLLM())
    
    findings = agent._analyze_protocol_anomalies("https://example.com:8443")
    
    # Should detect HTTPS on non-standard port
    assert len(findings) > 0
    assert any("Non-Standard Port" in f.title for f in findings)


def test_multiple_open_ports_detection():
    """Test detection of many open ports."""
    agent = NetworkAnalyzer(DummyLLM())
    context = base_context()
    
    # Simulate many open ports in recon data
    context.recon_data["raw"]["open_ports"] = list(range(20, 35))  # 15 ports
    
    findings = agent._check_port_scanning_behavior(context)
    
    assert len(findings) > 0
    assert any("Multiple Open Ports" in f.title for f in findings)


def test_data_exfiltration_pattern_detection():
    """Test detection of potential data exfiltration."""
    agent = NetworkAnalyzer(DummyLLM())
    context = base_context()
    
    # Add a finding that suggests data exposure
    context.findings.append(Finding(
        title="Sensitive Data Exposed",
        description="API keys leaked",
        severity="High",
        confidence=0.9,
        evidence="Found exposed credentials"
    ))
    
    findings = agent._detect_data_exfiltration_patterns(context)
    
    assert len(findings) > 0
    assert any("Exfiltration" in f.title for f in findings)


def test_llm_network_analysis():
    """Test LLM-powered network analysis."""
    llm = DummyLLM(json_responses=[
        {
            "additional_findings": [
                {
                    "title": "Suspicious C2 Pattern",
                    "description": "Regular beaconing detected",
                    "severity": "Critical",
                    "confidence": 0.8,
                    "evidence": "Connection every 60 seconds",
                    "mitigation": "Block C2 domain"
                }
            ]
        }
    ])
    
    agent = NetworkAnalyzer(llm)
    context = base_context()
    
    findings = agent._analyze_with_llm(context)
    
    assert len(findings) == 1
    assert "C2" in findings[0].title
    assert findings[0].severity == "Critical"


def test_full_network_analysis_run():
    """Test complete network analysis."""
    llm = DummyLLM(json_responses=[{"additional_findings": []}])
    agent = NetworkAnalyzer(llm)
    context = PentestContext(
        target="http://example.com:8080",
        mode="authorized",
        recon_data={"raw": {"open_ports": [22, 80, 443, 8080, 8443]}, "analysis": {}}
    )
    
    result = agent.run(context)
    
    # Should find issues
    assert len(result.findings) > 0
    # History should be updated
    assert any("Network traffic analysis" in h.get("message", "") for h in result.history)


def test_dns_analysis_localhost_skip():
    """Test that localhost DNS checks don't trigger false positives."""
    agent = NetworkAnalyzer(DummyLLM())
    
    # localhost should be OK with private IPs
    findings = agent._analyze_dns_patterns("http://localhost:8080")
    
    # Should not report private IP for localhost
    assert not any("Private IP" in f.title for f in findings)
