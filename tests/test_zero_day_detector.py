"""Tests for Zero-Day Detector."""

import pytest

from cortexsec.agents.zero_day_detector import ZeroDayDetector
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
        return {"potential_zero_days": []}


def base_context():
    return PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {}, "analysis": {}},
    )


def test_zero_day_detector_initialization():
    """Test zero-day detector initializes correctly."""
    agent = ZeroDayDetector(DummyLLM())
    
    assert agent.name == "ZeroDayDetector"


def test_behavioral_anomaly_detection():
    """Test detection of unusual behavior."""
    agent = ZeroDayDetector(DummyLLM())
    context = base_context()
    
    # Add findings with unusual behavior
    context.findings.append(Finding(
        title="Unusual Response",
        description="Server behaved strangely",
        severity="Medium",
        confidence=0.7,
        evidence="Unexpected error message with stack trace visible"
    ))
    
    findings = agent._detect_behavioral_anomalies(context)
    
    assert len(findings) > 0
    assert any("Anomal" in f.title for f in findings)


def test_crash_vulnerability_detection():
    """Test detection of crash indicators."""
    agent = ZeroDayDetector(DummyLLM())
    context = base_context()
    
    # Add findings with crash indicators
    context.findings.append(Finding(
        title="Server Error",
        description="Application crashed",
        severity="High",
        confidence=0.8,
        evidence="500 Internal Server Error with stack trace"
    ))
    
    findings = agent._perform_fuzzing_analysis(context)
    
    assert len(findings) > 0
    assert any("Crash" in f.title for f in findings)


def test_logic_flaw_detection():
    """Test detection of business logic vulnerabilities."""
    agent = ZeroDayDetector(DummyLLM())
    context = base_context()
    
    # Add findings suggesting logic flaws
    context.findings.append(Finding(
        title="Authentication Bypass",
        description="Can bypass login",
        severity="Critical",
        confidence=0.9,
        evidence="Login bypass via parameter manipulation"
    ))
    
    findings = agent._detect_logic_flaws(context)
    
    assert len(findings) > 0
    assert any("Logic" in f.title for f in findings)


def test_llm_zero_day_hunting():
    """Test LLM-powered zero-day hunting."""
    llm = DummyLLM(json_responses=[
        {
            "potential_zero_days": [
                {
                    "title": "Novel Memory Corruption",
                    "description": "Potential buffer overflow in custom parser",
                    "severity": "High",
                    "confidence": 0.6,
                    "evidence": "Unusual crash patterns",
                    "exploitation_theory": "Overflow could lead to RCE",
                    "mitigation": "Add bounds checking"
                }
            ]
        }
    ])
    
    agent = ZeroDayDetector(llm)
    context = base_context()
    
    findings = agent._use_llm_for_zero_day_hunting(context)
    
    assert len(findings) == 1
    assert "Zero-Day" in findings[0].title
    assert findings[0].confidence >= 0.4
    assert findings[0].confidence <= 0.7  # Zero-days should be uncertain


def test_full_zero_day_detection_run():
    """Test complete zero-day detection."""
    llm = DummyLLM(json_responses=[{"potential_zero_days": []}])
    agent = ZeroDayDetector(llm)
    context = base_context()
    
    # Add various findings
    context.findings.extend([
        Finding(
            title="Crash on Invalid Input",
            description="App crashes",
            severity="High",
            confidence=0.8,
            evidence="500 error"
        ),
        Finding(
            title="Privilege Escalation",
            description="Can escalate privileges",
            severity="Critical",
            confidence=0.9,
            evidence="User can access admin functions"
        )
    ])
    
    initial_count = len(context.findings)
    result = agent.run(context)
    
    # Should find potential zero-days
    assert len(result.findings) > initial_count
    # History should be updated
    assert any("Zero-day detection" in h.get("message", "") for h in result.history)


def test_no_findings_graceful_handling():
    """Test that agent handles no findings gracefully."""
    agent = ZeroDayDetector(DummyLLM())
    context = base_context()
    # No findings
    
    result = agent.run(context)
    
    # Should not crash
    assert isinstance(result, PentestContext)
