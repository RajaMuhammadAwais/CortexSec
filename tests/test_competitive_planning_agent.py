from cortexsec.agents.competitive_planning_agent import CompetitivePlanningAgent
from cortexsec.core.agent import Finding, PentestContext


class DummyLLM:
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        return ""


def test_competitive_planning_agent_generates_research_based_outputs():
    context = PentestContext(target="https://example.com", mode="authorized")
    context.findings = [
        Finding(title="SQLi", description="", severity="High", confidence=0.9, evidence="request/response"),
    ]
    context.attack_graph = {"confirmed_paths": 2, "causal_completeness": 1.0}
    context.payload_tests = [{"payload": "' OR '1'='1", "result": "blocked"}]
    context.recon_data = {"raw": {"headers": {"Server": "nginx"}}}
    context.exploitability_assessment = {"min_exploitability_confidence": 0.8}

    out = CompetitivePlanningAgent(DummyLLM()).run(context)

    assert "competitive_parity_matrix" in out.memory
    assert "competitive_maturity" in out.memory
    assert "competitive_initiatives" in out.memory
    assert "competitive_projects" in out.memory
    assert "competitive_research_references" in out.memory
    assert out.memory["competitive_summary"].startswith("Research-based roadmap")
    assert {"OWASP ZAP", "Burp Suite", "OWASP WSTG"}.issubset(out.memory["competitive_parity_matrix"].keys())
    assert 0.0 <= out.memory["competitive_maturity"]["overall"] <= 1.0
    assert any(item["priority"] == "P1" for item in out.memory["competitive_initiatives"])


def test_competitive_planning_agent_adds_parity_hardening_when_partial():
    context = PentestContext(target="https://example.com", mode="authorized")

    out = CompetitivePlanningAgent(DummyLLM()).run(context)

    initiative_names = [p["name"] for p in out.memory["competitive_initiatives"]]
    assert "Parity Hardening Sprint" in initiative_names
