import json

from cortexsec.agents.attack_simulation import AttackSimulationAgent
from cortexsec.agents.attack_surface_agent import AttackSurfaceAgent
from cortexsec.agents.exploitability_agent import ExploitabilityAgent
from cortexsec.agents.memory_agent import MemoryAgent
from cortexsec.agents.reasoning_agent import ReasoningAgent
from cortexsec.agents.recon import ReconAgent
from cortexsec.agents.report_agent import ReportAgent
from cortexsec.agents.risk_agent import RiskAgent
from cortexsec.agents.vuln_analysis import VulnAnalysisAgent
from cortexsec.core.agent import BaseAgent, Finding, PentestContext
from cortexsec.core.planner import SupervisorAgent


class DummyLLM:
    def __init__(self, text_response='{"findings": []}', json_response=None):
        self.text_response = text_response
        self.json_response = json_response or {}
        self.last_system_prompt = ""

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        self.last_system_prompt = system_prompt
        return self.text_response

    def generate_json(self, prompt: str, system_prompt: str = ""):
        self.last_system_prompt = system_prompt
        return self.json_response


class DummyResponse:
    def __init__(self, headers=None, status_code=200):
        self.headers = headers or {}
        self.status_code = status_code


class StaticAgent(BaseAgent):
    def __init__(self, name: str):
        super().__init__(name, DummyLLM())

    def run(self, context: PentestContext) -> PentestContext:
        context.history.append({"agent": self.name, "message": "ok"})
        return context


class FlakyAgent(BaseAgent):
    def __init__(self, name: str, fail_times: int):
        super().__init__(name, DummyLLM())
        self.fail_times = fail_times

    def run(self, context: PentestContext) -> PentestContext:
        if self.fail_times > 0:
            self.fail_times -= 1
            raise RuntimeError("transient failure")
        context.history.append({"agent": self.name, "message": "recovered"})
        return context


def base_context() -> PentestContext:
    return PentestContext(target="https://example.com", mode="authorized")


def test_recon_agent_positive_and_negative(monkeypatch):
    llm = DummyLLM(json_response={"technologies": ["nginx"], "potential_issues": [], "next_steps": []})
    agent = ReconAgent(llm)
    context = base_context()

    monkeypatch.setattr("requests.get", lambda *_args, **_kwargs: DummyResponse(headers={"Server": "nginx"}))
    out = agent.run(context)
    assert out.recon_data["raw"]["server"] == "nginx"
    assert "real-world authorized penetration testing practices" in llm.last_system_prompt
    assert "use terminal commands when required" in llm.last_system_prompt
    assert "multi-step investigative workflows autonomously" in llm.last_system_prompt
    assert "CAPTCHA" in llm.last_system_prompt
    assert "must not provide bot detection or CAPTCHA bypass" in llm.last_system_prompt

    def raise_error(*_args, **_kwargs):
        raise OSError("network down")

    monkeypatch.setattr("requests.get", raise_error)
    out = agent.run(context)
    assert "Failed to reach target" in out.recon_data["raw"]["error"]


def test_attack_surface_and_risk_agents():
    context = base_context()
    context.recon_data = {
        "raw": {"headers": {"Server": "nginx", "X-Powered-By": "php"}},
        "analysis": {"technologies": ["php"]},
    }
    context.findings = [
        Finding(title="A", description="", severity="High", confidence=0.8, evidence="x"),
        Finding(title="B", description="", severity="Medium", confidence=0.7, evidence="y"),
    ]

    surface = AttackSurfaceAgent(DummyLLM()).run(context)
    assert "web-server:nginx" in surface.attack_surface["exposed_services"]

    risk = RiskAgent(DummyLLM()).run(surface)
    assert risk.risk_summary["level"] == "Medium"


def test_vuln_analysis_positive_and_negative_paths():
    context = base_context()
    context.recon_data = {
        "raw": {"headers": {"Server": "nginx"}},
        "analysis": {"technologies": ["nginx"]},
    }

    llm = DummyLLM(
        json_response={
            "findings": [
                {
                    "title": "Weak config",
                    "description": "desc",
                    "severity": "High",
                    "confidence": 0.8,
                    "evidence": "e1",
                    "mitigation": "fix",
                    "cvss_score": 7.2,
                    "owasp_mapping": "A05",
                    "mitre_mapping": "T1190",
                }
            ]
        }
    )
    out = VulnAnalysisAgent(llm).run(context)
    assert any(f.title == "Weak config" for f in out.findings)
    assert any("Missing" in f.title for f in out.findings)
    assert "real-world authorized penetration testing practices" in llm.last_system_prompt
    assert "human-analyst workflow" in llm.last_system_prompt

    context.recon_data = {"raw": {"error": "timeout"}, "analysis": {}}
    out = VulnAnalysisAgent(llm).run(context)
    assert len(out.findings) >= 1  # keeps prior + llm findings, skips quick checks gracefully


def test_reasoning_exploitability_and_simulation_agents():
    context = base_context()
    context.findings = [
        Finding(title="Critical vuln", description="", severity="Critical", confidence=0.9, evidence="e", cvss_score=9.1),
        Finding(title="Low info", description="", severity="Low", confidence=0.6, evidence="f", cvss_score=2.0),
    ]

    out = ReasoningAgent(DummyLLM()).run(context)
    # 2026 Update: Expect 3 confirmed paths due to attack chaining on Critical finding
    assert out.attack_graph["confirmed_paths"] == 3

    out = ExploitabilityAgent(DummyLLM()).run(out)
    assert out.exploitability_assessment["analyzed_findings"] == 2
    assert all(f.analyzed for f in out.findings)

    out = AttackSimulationAgent(DummyLLM()).run(out)
    assert len(out.attack_simulation) == 2


def test_memory_agent_supports_file_without_parent_dir(tmp_path):
    context = base_context()
    context.findings = [Finding(title="A", description="", severity="Low", confidence=0.5, evidence="e")]
    context.orchestrator_learning = {"policy_scores": {"discovery": 2.0}, "reward_history": [0.2]}

    mem_file = tmp_path / "agent_memory.json"
    out = MemoryAgent(DummyLLM(), memory_path=str(mem_file)).run(context)

    data = json.loads(mem_file.read_text())
    assert data["total_runs"] == 1
    assert out.memory["recommended_focus"] == ["A"]


def test_report_agent_writes_markdown(tmp_path, monkeypatch):
    context = base_context()
    context.findings = [Finding(title="A", description="d", severity="Low", confidence=0.5, evidence="e")]
    monkeypatch.chdir(tmp_path)

    llm = DummyLLM(text_response="# Report")
    out = ReportAgent(llm).run(context)
    report = tmp_path / "reports" / "pentest_report.md"
    assert report.exists()
    assert "# Report" in report.read_text()
    assert "real-world authorized penetration testing practices" in llm.last_system_prompt
    assert "use terminal commands when required" in llm.last_system_prompt
    assert "approved automation integrations" in llm.last_system_prompt
    assert out.target == "https://example.com"


def test_supervisor_retries_failed_agent_and_records_recovery():
    context = base_context()
    agents = [
        FlakyAgent("ReconAgent", fail_times=1),
        StaticAgent("AttackSurfaceAgent"),
        StaticAgent("VulnAnalysisAgent"),
        StaticAgent("ReasoningAgent"),
        StaticAgent("ExploitabilityAgent"),
        StaticAgent("RiskAgent"),
        StaticAgent("AttackSimulationAgent"),
        StaticAgent("MemoryAgent"),
    ]

    supervisor = SupervisorAgent(DummyLLM(), agents, max_cycles=1, retry_failed_agents=1)
    out = supervisor.run(context)

    recovery = [e for e in out.memory.get("agent_recovery_log", []) if e.get("status") == "recovered"]
    assert recovery and recovery[0]["agent"] == "ReconAgent"
    assert out.stop_reason
