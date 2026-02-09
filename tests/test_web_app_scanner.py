"""Tests for Web Application Scanner Agent."""

import json

import pytest

from cortexsec.agents.web_app_scanner import WebAppScannerAgent
from cortexsec.core.agent import PentestContext


class DummyLLM:
    def __init__(self, json_response=None):
        self.json_response = json_response or {}
        self.last_system_prompt = ""

    def generate_json(self, prompt: str, system_prompt: str = ""):
        self.last_system_prompt = system_prompt
        return self.json_response


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}


def base_context():
    return PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {"headers": {}}, "analysis": {}},
    )


def test_graphql_introspection_detection(monkeypatch):
    """Test GraphQL introspection vulnerability detection."""
    context = base_context()

    def fake_post(url, *args, **kwargs):
        if "/graphql" in url and kwargs.get("json", {}).get("query"):
            return FakeResponse(
                text='{"data": {"__schema": {"types": [{"name": "User", "fields": [{"name": "id"}]}]}}}',
                status_code=200,
            )
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.post", fake_post)

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("GraphQL Introspection" in f.title for f in out.findings)
    graphql_finding = next(f for f in out.findings if "GraphQL Introspection" in f.title)
    assert graphql_finding.severity == "Medium"
    assert graphql_finding.confidence >= 0.9


def test_graphql_mutations_detection(monkeypatch):
    """Test detection of exposed GraphQL mutations."""
    context = base_context()

    def fake_post(url, *args, **kwargs):
        if "/graphql" in url:
            return FakeResponse(
                text='{"data": {"__schema": {"types": [{"name": "Mutation"}], "mutationType": {"name": "Mutation"}}}}',
                status_code=200,
            )
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.post", fake_post)

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("Mutations" in f.title for f in out.findings)


def test_jwt_none_algorithm_detection():
    """Test detection of JWT with 'none' algorithm."""
    context = base_context()
    
    # JWT with 'none' algorithm: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.
    context.recon_data["raw"]["headers"] = {
        "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0."
    }

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("none" in f.title.lower() for f in out.findings)
    none_finding = next(f for f in out.findings if "none" in f.title.lower())
    assert none_finding.severity == "Critical"


def test_jwt_missing_expiration():
    """Test detection of JWT without expiration claim."""
    context = base_context()
    
    # JWT without 'exp': eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.hash
    context.recon_data["raw"]["headers"] = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.dGVzdA"
    }

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("Expiration" in f.title for f in out.findings)


def test_csrf_missing_samesite():
    """Test detection of missing SameSite cookie attribute."""
    context = base_context()
    context.recon_data["raw"]["headers"] = {
        "Set-Cookie": "session=abc123; Path=/; HttpOnly"
    }

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("SameSite" in f.title for f in out.findings)
    samesite_finding = next(f for f in out.findings if "SameSite" in f.title)
    assert samesite_finding.severity == "High"


def test_session_cookie_missing_secure_flag():
    """Test detection of session cookie without Secure flag."""
    context = base_context()
    context.target = "https://example.com"
    context.recon_data["raw"]["headers"] = {
        "Set-Cookie": "sessionid=abc123; Path=/; HttpOnly; SameSite=Strict"
    }

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("Secure Flag" in f.title for f in out.findings)


def test_session_cookie_missing_httponly():
    """Test detection of session cookie without HttpOnly flag."""
    context = base_context()
    context.recon_data["raw"]["headers"] = {
        "Set-Cookie": "session=abc123; Path=/; Secure; SameSite=Strict"
    }

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("HttpOnly" in f.title for f in out.findings)


def test_file_upload_endpoint_detection(monkeypatch):
    """Test detection of file upload endpoints."""
    context = base_context()

    def fake_post(url, *args, **kwargs):
        if "/upload" in url:
            return FakeResponse(status_code=200, text='{"success": true}')
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.post", fake_post)

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("Upload" in f.title for f in out.findings)


def test_nosql_injection_detection(monkeypatch):
    """Test NoSQL injection vulnerability detection."""
    context = base_context()

    def fake_post(url, *args, **kwargs):
        data = kwargs.get("json", {})
        # Simulate successful injection
        if "/login" in url and isinstance(data.get("username"), dict):
            return FakeResponse(
                status_code=200,
                text='{"success": true, "token": "abc123", "authenticated": true}',
            )
        return FakeResponse(status_code=401)

    monkeypatch.setattr("requests.post", fake_post)

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("NoSQL" in f.title for f in out.findings)
    nosql_finding = next(f for f in out.findings if "NoSQL" in f.title)
    assert nosql_finding.severity == "Critical"


def test_web_scanner_skips_non_http_targets():
    """Test that scanner skips non-HTTP targets."""
    context = PentestContext(
        target="docker://container",
        mode="authorized",
        recon_data={"raw": {"headers": {}}, "analysis": {}},
    )

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    assert any("Skipped web app scanner" in h.get("message", "") for h in out.history)


def test_llm_analysis_integration(monkeypatch):
    """Test LLM-powered additional analysis."""
    context = base_context()

    llm = DummyLLM(
        json_response={
            "additional_insights": ["Chain CSRF with XSS"],
            "attack_chains": ["CSRF -> Account Takeover"],
            "priority_recommendations": ["Fix CSRF first"],
        }
    )

    # Create a finding
    context.recon_data["raw"]["headers"] = {
        "Set-Cookie": "session=abc; Path=/"
    }

    agent = WebAppScannerAgent(llm)
    out = agent.run(context)

    assert "web application security expert" in llm.last_system_prompt
    assert any(
        "Advanced web analysis complete" in h.get("message", "")
        for h in out.history
    )


def test_multiple_findings_aggregation(monkeypatch):
    """Test that multiple security issues are properly aggregated."""
    context = base_context()
    
    # JWT with issues
    context.recon_data["raw"]["headers"] = {
        "Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0.",
        "Set-Cookie": "session=abc; Path=/",
    }

    def fake_post(url, *args, **kwargs):
        if "/graphql" in url:
            return FakeResponse(
                text='{"data": {"__schema": {"types": [{"name": "User"}]}}}',
                status_code=200,
            )
        return FakeResponse(status_code=404)

    monkeypatch.setattr("requests.post", fake_post)

    agent = WebAppScannerAgent(DummyLLM())
    out = agent.run(context)

    # Should have JWT, GraphQL, and cookie findings
    assert len(out.findings) >= 3
    assert any("JWT" in f.title or "none" in f.title.lower() for f in out.findings)
    assert any("GraphQL" in f.title for f in out.findings)
    assert any("Cookie" in f.title or "SameSite" in f.title for f in out.findings)
