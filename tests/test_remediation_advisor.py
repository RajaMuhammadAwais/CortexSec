"""Tests for Remediation Advisor."""

import pytest

from cortexsec.agents.remediation_advisor import RemediationAdvisor
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
        return {
            "root_cause": "Test root cause",
            "fix_steps": ["Step 1", "Step 2"],
            "code_example": "# Fixed code",
            "config_changes": "security = true",
            "testing_steps": ["Test 1"],
            "prevention": "Follow best practices"
        }


def base_context():
    return PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {}, "analysis": {}},
    )


def test_remediation_advisor_initialization():
    """Test remediation advisor initializes correctly."""
    agent = RemediationAdvisor(DummyLLM())
    
    assert agent.name == "RemediationAdvisor"


def test_grouping_findings_by_type():
    """Test grouping similar findings together."""
    agent = RemediationAdvisor(DummyLLM())
    
    findings = [
        Finding(title="XSS in search", description="Test", severity="High", confidence=0.8, evidence="Found"),
        Finding(title="XSS in comments", description="Test", severity="High", confidence=0.7, evidence="Found"),
        Finding(title="SQL Injection in login", description="Test", severity="Critical", confidence=0.9, evidence="Found"),
    ]
    
    grouped = agent._group_findings_by_type(findings)
    
    # Should group XSS together
    assert "High_XSS" in grouped
    assert len(grouped["High_XSS"]) == 2


def test_prioritization():
    """Test remediation prioritization."""
    agent = RemediationAdvisor(DummyLLM())
    
    findings = [
        Finding(title="Low priority", description="Test", severity="Low", confidence=0.5, cvss_score=2.0, evidence="Found"),
        Finding(title="High priority", description="Test", severity="Critical", confidence=0.9, cvss_score=9.5, evidence="Found"),
        Finding(title="Medium priority", description="Test", severity="Medium", confidence=0.7, cvss_score=5.0, evidence="Found"),
    ]
    
    prioritized = agent._prioritize_remediation(findings)
    
    # Should be sorted by priority
    assert prioritized[0]["finding"].title == "High priority"
    assert prioritized[-1]["finding"].title == "Low priority"
    # Should have priority scores
    assert prioritized[0]["priority_score"] > prioritized[1]["priority_score"]


def test_xss_code_fix_generation():
    """Test generation of XSS fix code."""
    agent = RemediationAdvisor(DummyLLM())
    
    finding = Finding(
        title="XSS in output",
        description="User input reflected without sanitization",
        severity="High",
        confidence=0.9,
        evidence="Found XSS"
    )
    
    fix_code = agent._generate_code_fixes(finding)
    
    assert fix_code is not None
    assert "escape" in fix_code.lower()


def test_sql_injection_code_fix_generation():
    """Test generation of SQL injection fix code."""
    agent = RemediationAdvisor(DummyLLM())
    
    finding = Finding(
        title="SQL Injection in query",
        description="Direct SQL query with user input",
        severity="Critical",
        confidence=0.95,
        evidence="Found SQLi"
    )
    
    fix_code = agent._generate_code_fixes(finding)
    
    assert fix_code is not None
    assert "parameterized" in fix_code.lower() or "prepared" in fix_code.lower()


def test_infrastructure_fix_for_headers():
    """Test generation of infrastructure fixes for security headers."""
    agent = RemediationAdvisor(DummyLLM())
    
    finding = Finding(
        title="Missing Security Headers",
        description="X-Frame-Options not set",
        severity="Medium",
        confidence=0.8,
        evidence="Headers missing"
    )
    
    iac_fix = agent._generate_infrastructure_fixes(finding)
    
    assert iac_fix is not None
    assert "X-Frame-Options" in iac_fix or "nginx" in iac_fix.lower()


def test_remediation_plan_creation():
    """Test creation of full remediation plan."""
    agent = RemediationAdvisor(DummyLLM())
    context = base_context()
    
    # Add various findings
    context.findings = [
        Finding(title="Critical XSS", description="XSS vuln", severity="Critical", confidence=0.9, cvss_score=8.5, evidence="Found"),
        Finding(title="High SQLi", description="SQL vuln", severity="High", confidence=0.85, cvss_score=8.0, evidence="Found"),
        Finding(title="Medium CSRF", description="CSRF vuln", severity="Medium", confidence=0.7, cvss_score=5.5, evidence="Found"),
        Finding(title="Low Info Leak", description="Info leak", severity="Low", confidence=0.6, cvss_score=3.0, evidence="Found"),
    ]
    
    plan = agent._create_remediation_plan(context)
    
    assert plan["summary"]["total_findings"] == 4
    assert plan["summary"]["critical"] == 1
    assert plan["summary"]["high"] == 1
    assert len(plan["priority_order"]) > 0
    # Critical should be first
    assert plan["priority_order"][0]["severity"] == "Critical"


def test_llm_custom_fix_generation():
    """Test LLM-generated custom remediation."""
    llm = DummyLLM(json_responses=[
        {
            "root_cause": "Lack of input validation",
            "fix_steps": ["Add validation", "Sanitize input", "Test thoroughly"],
            "code_example": "if validate(input): process(sanitize(input))",
            "config_changes": "enable_validation=true",
            "testing_steps": ["Unit test", "Integration test"],
            "prevention": "Always validate user input"
        }
    ])
    
    agent = RemediationAdvisor(llm)
    finding = Finding(
        title="Input Validation Issue",
        description="No validation on user input",
        severity="High",
        confidence=0.8,
        evidence="Input accepted without checks"
    )
    
    guide = agent._use_llm_for_custom_fixes(finding)
    
    assert "Root Cause" in guide
    assert "Fix Steps" in guide
    assert "validate" in guide.lower()


def test_full_remediation_run():
    """Test complete remediation advisor run."""
    llm = DummyLLM()
    agent = RemediationAdvisor(llm)
    context = base_context()
    
    context.findings = [
        Finding(title="XSS Vulnerability", description="XSS issue", severity="High", confidence=0.9, cvss_score=7.5, evidence="Test"),
        Finding(title="SQL Injection", description="SQLi issue", severity="Critical", confidence=0.95, cvss_score=9.0, evidence="Test"),
    ]
    
    result = agent.run(context)
    
    # Should have remediation plan
    assert hasattr(result, "remediation_plan")
    assert "full_plan" in result.remediation_plan
    assert "detailed_fixes" in result.remediation_plan
    # History should be updated
    assert any("remediation plan" in h.get("message", "").lower() for h in result.history)


def test_no_findings_handling():
    """Test that agent handles no findings gracefully."""
    agent = RemediationAdvisor(DummyLLM())
    context = base_context()
    # No findings
    
    result = agent.run(context)
    
    # Should handle gracefully
    assert isinstance(result, PentestContext)
    assert any("No vulnerabilities" in h.get("message", "") for h in result.history)


def test_quick_wins_identification():
    """Test identification of quick win fixes."""
    agent = RemediationAdvisor(DummyLLM())
    context = base_context()
    
    context.findings = [
        Finding(title="Easy Fix", description="Easy", severity="Critical", confidence=0.95, cvss_score=9.0, evidence="Test"),
        Finding(title="Complex Fix", description="Complex", severity="Medium", confidence=0.6, cvss_score=5.0, evidence="Test"),
    ]
    
    plan = agent._create_remediation_plan(context)
    
    # Critical with high confidence should be a quick win
    assert len(plan["quick_wins"]) > 0
    assert plan["quick_wins"][0]["severity"] == "Critical"
