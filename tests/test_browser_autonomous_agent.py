"""Tests for Browser Autonomous Agent."""

import pytest

from cortexsec.agents.browser_autonomous_agent import BrowserAutonomousAgent, BrowserAction, BrowserObservation
from cortexsec.core.agent import PentestContext


class DummyLLM:
    def __init__(self, json_responses=None):
        self.json_responses = json_responses or []
        self.call_count = 0

    def generate_json(self, prompt: str, system_prompt: str = ""):
        if self.call_count < len(self.json_responses):
            response = self.json_responses[self.call_count]
            self.call_count += 1
            return response
        return {"action_type": "stop"}


def base_context():
    return PentestContext(
        target="https://example.com",
        mode="authorized",
        recon_data={"raw": {}, "analysis": {}},
    )


def test_browser_agent_initialization():
    """Test browser agent initializes correctly."""
    agent = BrowserAutonomousAgent(DummyLLM(), headless=True)
    
    assert agent.name == "BrowserAutonomousAgent"
    assert agent.headless is True
    assert agent.driver is None


def test_browser_action_dataclass():
    """Test BrowserAction dataclass."""
    action = BrowserAction(
        action_type="click",
        selector="#login-btn",
        value=None,
        reasoning="Test login button"
    )
    
    assert action.action_type == "click"
    assert action.selector == "#login-btn"
    assert action.reasoning == "Test login button"


def test_browser_observation_dataclass():
    """Test BrowserObservation dataclass."""
    observation = BrowserObservation(
        url="https://example.com/login",
        title="Login Page",
        dom_summary='{"forms": [], "inputs": []}',
        console_logs=["Error: test"]
    )
    
    assert observation.url == "https://example.com/login"
    assert observation.title == "Login Page"
    assert len(observation.console_logs) == 1


def test_decision_making_with_llm():
    """Test LLM-powered browser action decision making."""
    llm = DummyLLM(json_responses=[
        {
            "action_type": "click",
            "selector": "#search-btn",
            "value": None,
            "reasoning": "Test search functionality for XSS",
            "expected_vulnerability": "Reflected XSS"
        }
    ])
    
    agent = BrowserAutonomousAgent(llm, headless=True)
    
    observation = BrowserObservation(
        url="https://example.com",
        title="Home",
        dom_summary='{"buttons": [{"id": "search-btn"}]}'
    )
    
    context = base_context()
    action = agent._decide_next_action(observation, context)
    
    assert action is not None
    assert action.action_type == "click"
    assert action.selector == "#search-btn"
    assert "XSS" in action.reasoning


def test_stop_decision():
    """Test that agent can decide to stop testing."""
    llm = DummyLLM(json_responses=[
        {"action_type": "stop"}
    ])
    
    agent = BrowserAutonomousAgent(llm, headless=True)
    
    observation = BrowserObservation(
        url="https://example.com",
        title="Test",
        dom_summary="{}"
    )
    
    context = base_context()
    action = agent._decide_next_action(observation, context)
    
    assert action is None


def test_non_http_target_skipped():
    """Test that non-HTTP targets are skipped."""
    agent = BrowserAutonomousAgent(DummyLLM(), headless=True)
    
    context = PentestContext(
        target="ftp://example.com",
        mode="authorized"
    )
    
    result = agent.run(context)
    
    # Should skip without initializing browser
    assert agent.driver is None


def test_selenium_not_available_handling():
    """Test graceful handling when Selenium is not available."""
    # This test will pass regardless of Selenium availability
    agent = BrowserAutonomousAgent(DummyLLM(), headless=True)
    context = base_context()
    
    # Should not crash
    result = agent.run(context)
    
    assert isinstance(result, PentestContext)


def test_multiple_browser_actions():
    """Test sequence of browser actions."""
    llm = DummyLLM(json_responses=[
        {
            "action_type": "navigate",
            "value": "https://example.com/login",
            "reasoning": "Navigate to login page"
        },
        {
            "action_type": "type",
            "selector": "#username",
            "value": "test@example.com",
            "reasoning": "Enter test email"
        },
        {
            "action_type": "click",
            "selector": "#submit",
            "reasoning": "Submit login form"
        },
        {
            "action_type": "stop"
        }
    ])
    
    agent = BrowserAutonomousAgent(llm, headless=True)
    
    # Test decision sequence
    context = base_context()
    observation = BrowserObservation(url="https://example.com", title="Home", dom_summary="{}")
    
    action1 = agent._decide_next_action(observation, context)
    assert action1.action_type == "navigate"
    
    action2 = agent._decide_next_action(observation, context)
    assert action2.action_type == "type"
    
    action3 = agent._decide_next_action(observation, context)
    assert action3.action_type == "click"
    
    action4 = agent._decide_next_action(observation, context)
    assert action4 is None  # Stop


def test_vulnerability_analysis():
    """Test LLM-based vulnerability analysis."""
    llm = DummyLLM(json_responses=[
        {
            "findings": [
                {
                    "title": "Missing CSRF Protection",
                    "description": "Form lacks CSRF token",
                    "severity": "High",
                    "confidence": 0.85,
                    "evidence": "No hidden token field found",
                    "mitigation": "Implement CSRF tokens"
                }
            ]
        }
    ])
    
    agent = BrowserAutonomousAgent(llm, headless=True)
    
    observation = BrowserObservation(
        url="https://example.com/login",
        title="Login",
        dom_summary='{"forms": [{"action": "/login", "method": "POST"}]}',
        console_logs=[]
    )
    
    actions = [
        BrowserAction(action_type="navigate", reasoning="Test navigation")
    ]
    
    findings = agent._analyze_for_vulnerabilities(observation, actions)
    
    assert len(findings) == 1
    assert "CSRF" in findings[0].title
    assert findings[0].severity == "High"
    assert findings[0].confidence == 0.85
