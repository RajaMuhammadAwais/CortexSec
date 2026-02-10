import json

from cortexsec.agents.attack_simulation import AttackSimulationAgent
from cortexsec.agents.attack_surface_agent import AttackSurfaceAgent
from cortexsec.agents.exploitability_agent import ExploitabilityAgent
from cortexsec.agents.memory_agent import MemoryAgent
from cortexsec.agents.payload_agent import PayloadAgent
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
    def __init__(self, headers=None, status_code=200, text=""):
        self.headers = headers or {}
        self.status_code = status_code
        self.text = text


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
    assert "crawled_urls" in out.recon_data["raw"]
    assert "directory_hits" in out.recon_data["raw"]
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
        StaticAgent("PayloadAgent"),
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


def test_payload_agent_generates_safe_payload_results(monkeypatch):
    context = base_context()
    context.attack_surface = {"entry_points": ["/api/test"]}

    class FakeResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    def fake_get(*_args, **_kwargs):
        if "params" in _kwargs and _kwargs["params"].get("q") == "CORTEX_CANARY_03_f4ad":
            return FakeResponse("baseline CORTEX_CANARY_03_f4ad")
        return FakeResponse("baseline")

    def fake_post(*_args, **_kwargs):
        return FakeResponse("baseline")

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.post", fake_post)

    out = PayloadAgent(DummyLLM()).run(context)
    # 2 endpoints (target + discovered) * 5 payloads * 4 vectors
    assert len(out.payload_tests) == 40
    assert any(p["status"] in {"needs-review", "weak-signal"} for p in out.payload_tests)
    assert all("perturbation_score" in p.get("evidence", {}) for p in out.payload_tests)
    assert all(p["request_mode"] in {"query", "json", "form", "header-auth"} for p in out.payload_tests)


def test_vuln_analysis_ingests_payload_signals():
    context = base_context()
    context.recon_data = {"raw": {"headers": {"Server": "nginx"}}, "analysis": {}}
    context.payload_tests = [
        {
            "payload_type": "logic-test",
            "status": "needs-review",
            "goal": "Authorization boundary checks",
            "evidence": {"status_changed": True},
        }
    ]

    out = VulnAnalysisAgent(DummyLLM(json_response={"findings": []})).run(context)
    assert any(f.title.startswith("Payload-Test Signal") for f in out.findings)




def test_payload_agent_includes_llm_generated_payloads(monkeypatch):
    context = base_context()

    class FakeResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    llm = DummyLLM(json_response={
        "payloads": [
            {"payload_type": "canary", "value": "CORTEX_DYNAMIC_SAFE", "goal": "trace", "hypothesis": "reflect"},
            {"payload_type": "logic-test", "value": "role=user", "goal": "auth", "hypothesis": "boundary"},
        ]
    })

    monkeypatch.setattr("requests.get", lambda *_a, **_k: FakeResponse("ok"))
    monkeypatch.setattr("requests.post", lambda *_a, **_k: FakeResponse("ok"))

    out = PayloadAgent(llm).run(context)
    payload_values = {entry["payload"] for entry in out.payload_tests}

    assert "CORTEX_DYNAMIC_SAFE" in payload_values
    assert "role=user" in payload_values

def test_payload_agent_destructive_mode_is_plan_only(monkeypatch):
    context = PentestContext(target="https://example.com", mode="authorized", pro_user=True, destructive_mode=True)

    class FakeResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    monkeypatch.setattr("requests.get", lambda *_a, **_k: FakeResponse("ok"))
    monkeypatch.setattr("requests.post", lambda *_a, **_k: FakeResponse("ok"))

    out = PayloadAgent(DummyLLM()).run(context)
    assert any("execution blocked" in h.get("message", "") for h in out.history)


def test_attack_simulation_includes_destructive_plan_when_enabled():
    context = PentestContext(target="https://example.com", mode="authorized", pro_user=True, destructive_mode=True)
    context.findings = [Finding(title="A", description="d", severity="Low", confidence=0.5, evidence="e")]
    out = AttackSimulationAgent(DummyLLM()).run(context)
    assert out.attack_simulation[0]["destructive_mode"] is True
    assert out.attack_simulation[0]["destructive_plan"]


def test_cli_destructive_requires_pro_user():
    from typer.testing import CliRunner
    from cortexsec.cli.main import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "--target", "http://localhost:8080", "--mode", "lab", "--destructive-mode"
    ])
    assert result.exit_code == 1
    assert "requires --pro-user" in result.stdout


def test_vuln_analysis_embeds_scientific_logic():
    context = base_context()
    context.recon_data = {"raw": {"headers": {"Server": "nginx"}}, "analysis": {}}
    context.payload_tests = [
        {"status": "needs-review"},
        {"status": "inconclusive"},
        {"status": "no-strong-signal"},
    ]

    llm = DummyLLM(json_response={"findings": [{"title": "A", "description": "d", "severity": "High", "confidence": 0.6, "evidence": "e"}]})
    out = VulnAnalysisAgent(llm).run(context)

    assert out.scientific_analysis["hypothesis_matrix"]["tests_total"] == 3
    assert out.scientific_analysis["false_positive_risk"] in {"low", "medium", "high"}
    assert all(0.0 <= f.confidence <= 1.0 for f in out.findings)


def test_payload_agent_control_suppresses_false_positive_signal(monkeypatch):
    context = base_context()

    class FakeResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    agent = PayloadAgent(DummyLLM())

    def fake_execute(_url, _vector, value):
        # payload and control behave similarly (no payload-specific perturbation)
        if value == "CORTEX_CTRL_NEUTRAL":
            return FakeResponse("forbidden", status_code=403)
        return FakeResponse("forbidden", status_code=403)

    monkeypatch.setattr(agent, "_execute_vector", fake_execute)

    out = agent._run_vector(
        "https://example.com",
        payload=agent._payloads()[0],
        vector="query",
        baseline={"status_code": 200, "body_length": 8},
    )

    assert out["status"] in {"no-strong-signal", "weak-signal"}
    assert out["evidence"]["control_authorization_signal"] is True


def test_payload_agent_marks_reproducible_when_replay_matches(monkeypatch):
    class FakeResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    agent = PayloadAgent(DummyLLM())
    payload = agent._payloads()[0]

    calls = {"n": 0}

    def fake_execute(_url, _vector, value):
        if value == "CORTEX_CTRL_NEUTRAL":
            return FakeResponse("baseline", 200)
        calls["n"] += 1
        # payload + replay return same behavior
        return FakeResponse(f"baseline {payload.value}", 500)

    monkeypatch.setattr(agent, "_execute_vector", fake_execute)

    out = agent._run_vector(
        "https://example.com",
        payload=payload,
        vector="query",
        baseline={"status_code": 200, "body_length": 8},
    )

    assert out["status"] == "needs-review"
    assert out["evidence"]["reproducible"] is True


def test_supervisor_complete_flow_positive(monkeypatch, tmp_path):
    class FakeResponse:
        def __init__(self, text="ok", status_code=200, headers=None):
            self.text = text
            self.status_code = status_code
            self.headers = headers or {"Server": "nginx", "X-Powered-By": "python"}

    def fake_get(url, *args, **kwargs):
        params = kwargs.get("params") or {}
        headers = kwargs.get("headers") or {}
        q = params.get("q", "")

        body = "baseline"
        code = 200
        if "CORTEX_CANARY_03_f4ad" in q or "CORTEX_CANARY_03_f4ad" in headers.get("X-Pentest-Input", ""):
            body = "baseline CORTEX_CANARY_03_f4ad"
            code = 500
        return FakeResponse(text=body, status_code=code)

    def fake_post(_url, *args, **kwargs):
        payload = (kwargs.get("json") or {}).get("input") or (kwargs.get("data") or {}).get("input") or ""
        if payload == "CORTEX_CANARY_03_f4ad":
            return FakeResponse(text="baseline CORTEX_CANARY_03_f4ad", status_code=500)
        return FakeResponse(text="baseline", status_code=200)

    monkeypatch.setattr("requests.get", fake_get)
    monkeypatch.setattr("requests.post", fake_post)
    monkeypatch.chdir(tmp_path)

    llm = DummyLLM(text_response="# Report", json_response={"findings": []})
    agents = [
        ReconAgent(llm),
        AttackSurfaceAgent(llm),
        PayloadAgent(llm),
        VulnAnalysisAgent(llm),
        ReasoningAgent(llm),
        ExploitabilityAgent(llm),
        RiskAgent(llm),
        AttackSimulationAgent(llm),
        MemoryAgent(llm),
        ReportAgent(llm),
    ]

    supervisor = SupervisorAgent(llm, agents, max_cycles=1, retry_failed_agents=0)
    out = supervisor.run(PentestContext(target="https://example.com", mode="authorized"))

    assert out.stop_reason
    assert out.payload_tests
    assert out.findings
    assert out.risk_summary.get("level") in {"Low", "Medium", "High", "Critical"}
    assert (tmp_path / "reports" / "pentest_report.md").exists()


def test_supervisor_complete_flow_negative_network_failures(monkeypatch, tmp_path):
    def fail_request(*_args, **_kwargs):
        raise OSError("network down")

    monkeypatch.setattr("requests.get", fail_request)
    monkeypatch.setattr("requests.post", fail_request)
    monkeypatch.chdir(tmp_path)

    llm = DummyLLM(text_response="# Report", json_response={"findings": []})
    agents = [
        ReconAgent(llm),
        AttackSurfaceAgent(llm),
        PayloadAgent(llm),
        VulnAnalysisAgent(llm),
        ReasoningAgent(llm),
        ExploitabilityAgent(llm),
        RiskAgent(llm),
        AttackSimulationAgent(llm),
        MemoryAgent(llm),
        ReportAgent(llm),
    ]

    supervisor = SupervisorAgent(llm, agents, max_cycles=1, retry_failed_agents=0)
    out = supervisor.run(PentestContext(target="https://example.com", mode="authorized"))

    assert out.stop_reason
    assert out.recon_data.get("raw", {}).get("error")
    assert out.payload_tests
    assert any(t.get("status") == "inconclusive" for t in out.payload_tests)
    assert (tmp_path / "reports" / "pentest_report.md").exists()


def test_supervisor_extends_when_findings_required_but_none_present():
    context = base_context()
    context.require_findings_before_stop = True
    context.max_no_finding_extensions = 2

    agents = [StaticAgent("ReconAgent")]
    supervisor = SupervisorAgent(DummyLLM(), agents, max_cycles=1, retry_failed_agents=0)

    out = supervisor.run(context)

    assert out.memory.get("no_finding_extensions_used") == 2
    assert "max cycles (3)" in out.stop_reason


def test_supervisor_does_not_extend_when_findings_exist():
    context = base_context()
    context.require_findings_before_stop = True
    context.max_no_finding_extensions = 3
    context.findings = [Finding(title="Signal", description="d", severity="Low", confidence=0.6, evidence="e")]

    agents = [StaticAgent("ReconAgent")]
    supervisor = SupervisorAgent(DummyLLM(), agents, max_cycles=1, retry_failed_agents=0)

    out = supervisor.run(context)

    assert out.memory.get("no_finding_extensions_used") == 0
    assert "max cycles (1)" in out.stop_reason
