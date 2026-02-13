import json

from cortexsec.tools.base import ToolAdapter, ToolManager


class DummyAdapter(ToolAdapter):
    name = "dummy"

    def build_command(self, target: str, options: str = "") -> list[str]:
        return ["echo", f"{target}:{options}"]

    def parse_output(self, stdout: str, stderr: str, exit_code: int, target: str):
        return {"tool": self.name, "target": target, "status": "ok", "exit_code": exit_code}


def test_tool_manager_invoke_json_routes_to_adapter():
    manager = ToolManager({"dummy": DummyAdapter()})
    result = manager.invoke_json(json.dumps({"tool": "dummy", "target": "example.com", "options": "-x"}))
    assert result["tool"] == "dummy"
    assert result["target"] == "example.com"


def test_tool_manager_rejects_unknown_tool():
    manager = ToolManager({"dummy": DummyAdapter()})
    try:
        manager.invoke({"tool": "unknown", "target": "example.com"})
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "Unsupported tool" in str(exc)


def test_tool_manager_blocks_unsafe_option_in_safe_mode():
    manager = ToolManager({"dummy": DummyAdapter()})
    result = manager.invoke({"tool": "dummy", "target": "example.com", "options": "--os-shell", "safe_mode": True})
    assert result["status"] == "blocked"
    assert result["error"] == "safe-mode-policy-blocked"


def test_tool_manager_allows_unsafe_option_when_safe_mode_disabled():
    manager = ToolManager({"dummy": DummyAdapter()})
    result = manager.invoke({"tool": "dummy", "target": "example.com", "options": "--os-shell", "safe_mode": False})
    assert result["status"] == "ok"
