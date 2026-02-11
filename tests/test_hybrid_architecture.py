from cortexsec.api.contracts import AssessmentRequest
from cortexsec.plugins.base import PluginContext, PluginRegistry, SecurityPlugin
from cortexsec.telemetry.benchmark import BenchmarkRecorder


class EchoPlugin(SecurityPlugin):
    plugin_id = "echo.plugin"

    def run(self, context: PluginContext):
        return {"target": context.request.target, "ok": True}


def test_plugin_registry_run_many_returns_reports():
    registry = PluginRegistry()
    registry.register(EchoPlugin())

    reports = registry.run_many(
        ["echo.plugin"],
        PluginContext(request=AssessmentRequest(target="http://localhost:8080")),
    )
    assert reports["echo.plugin"]["ok"] is True


def test_benchmark_recorder_snapshot_contains_duration_and_counters():
    recorder = BenchmarkRecorder()
    recorder.incr("plugin_runs")
    recorder.note("phase", "beta")

    snapshot = recorder.snapshot()
    assert "duration_ms" in snapshot
    assert snapshot["counters"]["plugin_runs"] == 1
    assert snapshot["annotations"]["phase"] == "beta"
