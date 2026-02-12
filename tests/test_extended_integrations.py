import pytest
from cortexsec.api.contracts import AssessmentRequest
from cortexsec.api.service import AssessmentService
from cortexsec.plugins import NucleiPlugin, SqlmapPlugin, NiktoPlugin, GobusterPlugin

def test_plugin_registration():
    service = AssessmentService()
    available = list(service.plugins.available())
    assert "scanner.nuclei" in available
    assert "scanner.sqlmap" in available
    assert "scanner.nikto" in available
    assert "scanner.gobuster" in available
    assert isinstance(service.plugins.get("scanner.nuclei"), NucleiPlugin)

def test_nuclei_adapter_parsing():
    from cortexsec.tools.extended_adapters import NucleiAdapter
    adapter = NucleiAdapter()
    stdout = '{"info":{"name":"test-finding","severity":"high","description":"test desc"},"matched-at":"http://example.com"}'
    result = adapter.parse_output(stdout, "", 0, "http://example.com")
    assert result["status"] == "ok"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "test-finding"
    assert result["findings"][0]["severity"] == "high"

def test_sqlmap_adapter_parsing():
    from cortexsec.tools.extended_adapters import SqlmapAdapter
    adapter = SqlmapAdapter()
    stdout = "Target is vulnerable to SQL injection"
    result = adapter.parse_output(stdout, "", 0, "http://example.com")
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "sql_injection"

def test_nikto_adapter_parsing():
    from cortexsec.tools.extended_adapters import NiktoAdapter
    adapter = NiktoAdapter()
    stdout = "+ OSVDB-3092: /admin/: This might be interesting."
    result = adapter.parse_output(stdout, "", 0, "http://example.com")
    assert len(result["findings"]) == 1
    assert "OSVDB-3092" in result["findings"][0]["evidence"]

def test_gobuster_adapter_parsing():
    from cortexsec.tools.extended_adapters import GobusterAdapter
    adapter = GobusterAdapter()
    stdout = "/admin (Status: 200)"
    result = adapter.parse_output(stdout, "", 0, "http://example.com")
    assert len(result["findings"]) == 1
    assert "/admin" in result["findings"][0]["evidence"]
